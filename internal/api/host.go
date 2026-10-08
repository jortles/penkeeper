package api

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

const maxNmapUploadSize = 10 << 20 // 10 MB

// hostIdentifierRe allows IPs, CIDRs, hostnames — no shell metacharacters.
var hostIdentifierRe = regexp.MustCompile(`^[a-zA-Z0-9.\-:/]+$`)

// validHostIdentifier reports whether identifier is acceptable. Host
// identifiers commonly feed external scanning workflows, so they are
// restricted to IP/CIDR/hostname characters.
func validHostIdentifier(identifier string) bool {
	return hostIdentifierRe.MatchString(identifier)
}

// identifierErrMsg is the error for an identifier validHostIdentifier rejects.
const identifierErrMsg = "identifier must contain only alphanumeric characters, dots, hyphens, colons, or slashes"

// -------------------------------------------------------------------
// Payload for creating a host
// -------------------------------------------------------------------
type createHostReq struct {
	Identifier string `json:"identifier" binding:"required"`
	Label      string `json:"label"`
	DeviceType string `json:"device_type"`
	OS         string `json:"os"`
}

// -------------------------------------------------------------------
// CreateHost – POST /assessments/:eid/hosts
// -------------------------------------------------------------------
func CreateHost(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		engID, err := uuid.Parse(c.Param("eid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assessment id"})
			return
		}

		if verifyAssessmentOwner(db, engID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
			return
		}

		var req createHostReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
			return
		}

		if !validHostIdentifier(req.Identifier) {
			c.JSON(http.StatusBadRequest, gin.H{"error": identifierErrMsg})
			return
		}

		host := model.Host{
			ID:           uuid.New(),
			AssessmentID: engID,
			Identifier:   req.Identifier,
			Label:        req.Label,
			DeviceType:   req.DeviceType,
			OS:           req.OS,
		}
		if err := db.Create(&host).Error; err != nil {
			log.Printf("CreateHost DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store host"})
			return
		}
		go RecordActivity(db, engID, userID, "host_added", "Added host "+req.Identifier)
		c.JSON(http.StatusCreated, host)
	}
}

// -------------------------------------------------------------------
// ListHosts – GET /assessments/:eid/hosts
// -------------------------------------------------------------------
func ListHosts(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		engID, err := uuid.Parse(c.Param("eid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assessment id"})
			return
		}

		if verifyAssessmentOwner(db, engID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
			return
		}

		var hosts []model.Host
		if err := db.Where("assessment_id = ?", engID).Find(&hosts).Error; err != nil {
			log.Printf("ListHosts DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch hosts"})
			return
		}
		c.JSON(http.StatusOK, hosts)
	}
}

// -------------------------------------------------------------------
// Helper: preload a host with its related collections
// -------------------------------------------------------------------
func preloadHost(db *storage.DB, hid uuid.UUID) (model.Host, error) {
	var host model.Host
	err := db.Preload("Ports").
		Preload("Creds").
		Preload("Notes").
		Preload("ToolOutputs").
		First(&host, "id = ?", hid).Error
	if err == nil {
		// Decrypt credential passwords and hashes for the response. On
		// failure, blank the field rather than leaking the stored ciphertext
		// (GET /hosts/:hid/credentials flags such values).
		for i := range host.Creds {
			host.Creds[i] = decryptCredential(host.Creds[i]).Credential
		}
	}
	return host, err
}

// -------------------------------------------------------------------
// GetHost – GET /hosts/:hid
// Returns host + ports + credentials + notes
// -------------------------------------------------------------------
func GetHost(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		if verifyHostOwner(db, hid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		host, err := preloadHost(db, hid)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}
		c.JSON(http.StatusOK, host)
	}
}

// -------------------------------------------------------------------
// Nmap XML structures (only the bits we need)
// -------------------------------------------------------------------
type nmapRun struct {
	XMLName  xml.Name   `xml:"nmaprun"`
	Hosts    []nmapHost `xml:"host"`
	RunStats struct {
		Hosts struct {
			// Targets scanned, up or not. A string, so an odd value in a
			// hand-made file is ignored instead of rejecting the file.
			Total string `xml:"total,attr"`
		} `xml:"hosts"`
	} `xml:"runstats"`
}

// targets returns how many targets the scan covered according to its run
// statistics, or 0 when the file doesn't say.
func (r nmapRun) targets() int {
	n, err := strconv.Atoi(strings.TrimSpace(r.RunStats.Hosts.Total))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	// Type is "user" for a name nmap was given as a target and resolved to
	// the entry's address, "PTR" for the address's reverse-DNS name, which
	// may be stale (another machine's old name).
	Type string `xml:"type,attr"`
}

type nmapHost struct {
	Status struct {
		State  string `xml:"state,attr"`  // up, down, unknown or skipped
		Reason string `xml:"reason,attr"` // "user-set" when -Pn made nmap treat the target as up
	} `xml:"status"`
	Addresses []nmapAddress  `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     []nmapPort     `xml:"ports>port"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`

	State struct {
		State string `xml:"state,attr"`
	} `xml:"state"`

	Service struct {
		Name      string `xml:"name,attr"`
		Product   string `xml:"product,attr"`
		Version   string `xml:"version,attr"`
		ExtraInfo string `xml:"extrainfo,attr"`
		Method    string `xml:"method,attr"` // "probed" (-sV) or "table" (guessed from the port number)
	} `xml:"service"`

	Scripts []nmapScript `xml:"script"`
}

// nmapFileError reports a problem with the uploaded file itself (not XML,
// not an Nmap report, no matching host). Handlers answer it with 400.
type nmapFileError struct{ msg string }

func (e *nmapFileError) Error() string { return e.msg }

// parseNmapXML decodes an uploaded Nmap XML report. Every error it returns
// is an *nmapFileError.
func parseNmapXML(data []byte) (nmapRun, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		if errors.Is(err, io.EOF) {
			return run, &nmapFileError{"invalid nmap XML: the file contains no XML elements"}
		}
		// e.g. "expected element type <nmaprun> but have <NessusClientData_v2>"
		return run, &nmapFileError{"invalid nmap XML: " + err.Error()}
	}
	return run, nil
}

// state is the host's status as nmap reported it. Verbose (-v) and list
// (-sL) scans also write down/unknown hosts; a missing <status> (hand-made
// files) counts as up.
func (h nmapHost) state() string {
	if h.Status.State == "" {
		return "up"
	}
	return h.Status.State
}

// up reports whether nmap saw the host up.
func (h nmapHost) up() bool { return h.state() == "up" }

// seen reports whether nmap found the host up: by itself or, when -Pn made
// it report every target up without a check (reason "user-set"), through
// an open port to import. An entry that was not seen, such as an address a
// stale PTR record still names, is never created by a bulk import and
// never competes with a seen entry for a hostname, unless it was scanned
// as that name and the seen entries only have it as a PTR record (see
// nmapHostsFor).
func (h nmapHost) seen() bool {
	if !h.up() {
		return false
	}
	valid, _ := h.openPorts()
	return h.Status.Reason != "user-set" || valid > 0
}

// matches reports whether the entry is the one identifier names: an IP
// address identifier must be one of the entry's addresses (a hostname that
// happens to read like it does not count), any other identifier one of its
// hostnames (case-insensitive).
func (h nmapHost) matches(identifier string) bool {
	if _, err := netip.ParseAddr(identifier); err == nil {
		return h.matchesAddress(identifier)
	}
	return h.matchesHostname(identifier)
}

// matchesAddress reports whether identifier is one of the host's IP
// addresses. addrtype is ipv4 (the DTD default when absent), ipv6 or mac;
// a MAC address is never a host identifier.
func (h nmapHost) matchesAddress(identifier string) bool {
	for _, a := range h.Addresses {
		if a.AddrType != "mac" && sameIPAddress(a.Addr, identifier) {
			return true
		}
	}
	return false
}

// matchesHostname reports whether identifier is one of the host's names.
func (h nmapHost) matchesHostname(identifier string) bool {
	for _, hn := range h.Hostnames {
		if hn.Name != "" && strings.EqualFold(hn.Name, identifier) {
			return true
		}
	}
	return false
}

// scannedAs reports whether nmap was given name as a target and resolved it
// to this entry's address (hostname type "user"), rather than only finding
// it as the address's PTR record.
func (h nmapHost) scannedAs(name string) bool {
	for _, hn := range h.Hostnames {
		if hn.Type == "user" && hn.Name != "" && strings.EqualFold(hn.Name, name) {
			return true
		}
	}
	return false
}

// name is how the import refers to the host: its first IP address, else
// its first hostname, else whatever address it has.
func (h nmapHost) name() string {
	for _, a := range h.Addresses {
		if a.AddrType != "mac" && a.Addr != "" {
			return a.Addr
		}
	}
	for _, hn := range h.Hostnames {
		if hn.Name != "" {
			return hn.Name
		}
	}
	if len(h.Addresses) > 0 && h.Addresses[0].Addr != "" {
		return h.Addresses[0].Addr
	}
	return "(no address)"
}

// key identifies the machine an entry describes, so repeated entries for
// one address (masscan writes one per port) count as one host.
func (h nmapHost) key() string {
	n := h.name()
	if ip, err := netip.ParseAddr(n); err == nil {
		return ip.String()
	}
	return strings.ToLower(n)
}

// inPrefix reports whether one of the host's IP addresses lies in prefix.
func (h nmapHost) inPrefix(prefix netip.Prefix) bool {
	for _, a := range h.Addresses {
		if ip, err := netip.ParseAddr(a.Addr); err == nil && a.AddrType != "mac" && prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// openPorts counts the host's open ports that can be imported (valid) and
// those with an invalid number or protocol.
func (h nmapHost) openPorts() (valid, invalid int) {
	for _, np := range h.Ports {
		if np.State.State != "open" {
			continue
		}
		if _, _, ok := nmapPortKey(np); ok {
			valid++
		} else {
			invalid++
		}
	}
	return valid, invalid
}

// bulkIdentifier is the identifier a bulk import gives the host: its IPv4
// address, else its IPv6 address, else any address ("" if it has none).
func (h nmapHost) bulkIdentifier() string {
	for _, want := range []string{"ipv4", "ipv6"} {
		for _, a := range h.Addresses {
			if a.AddrType == want {
				return a.Addr
			}
		}
	}
	if len(h.Addresses) > 0 {
		return h.Addresses[0].Addr
	}
	return ""
}

// nmapHostNames lists hosts for a message (each machine once, at most five).
func nmapHostNames(hosts []nmapHost) string {
	seen := map[string]bool{}
	var names []string
	for _, nh := range hosts {
		if k := nh.key(); !seen[k] {
			seen[k] = true
			names = append(names, nh.name())
		}
	}
	if len(names) > 5 {
		return fmt.Sprintf("%s and %d more", strings.Join(names[:5], ", "), len(names)-5)
	}
	return strings.Join(names, ", ")
}

// nmapMachines counts the machines (distinct addresses) among entries.
func nmapMachines(hosts []nmapHost) int {
	seen := map[string]bool{}
	for _, nh := range hosts {
		seen[nh.key()] = true
	}
	return len(seen)
}

// nmapSharedNames returns the hostnames (lower case) that seen entries
// with different addresses share: an HA pair's or a reassigned address's
// PTR name, or a name --resolve-all scanned on each of its addresses. Such
// a name does not tell the machines apart, so a bulk import never matches
// an existing host by it. As in nmapHostsFor, an entry that was not seen
// still counts for a name it was scanned as (see scannedAs) if no seen
// entry was scanned as it, so a seen entry that only has that name as its
// PTR record never updates the host named after the target.
func nmapSharedNames(hosts []nmapHost) map[string]bool {
	scanned := map[string]bool{} // names a seen entry was scanned as
	for _, nh := range hosts {
		for _, hn := range nh.Hostnames {
			if hn.Type == "user" && nh.seen() {
				scanned[strings.ToLower(hn.Name)] = true
			}
		}
	}
	first := map[string]string{} // hostname -> address of the first entry with it
	shared := map[string]bool{}
	for _, nh := range hosts {
		addr := nh.bulkIdentifier()
		if !nh.up() || addr == "" {
			continue // down: not imported
		}
		saw := nh.seen()
		if ip, err := netip.ParseAddr(addr); err == nil {
			addr = ip.String()
		}
		for _, hn := range nh.Hostnames {
			name := strings.ToLower(hn.Name)
			if !saw && (hn.Type != "user" || scanned[name]) {
				continue // -Pn without an open port: not imported
			}
			switch prev, seen := first[name]; {
			case name == "":
			case !seen:
				first[name] = addr
			case prev != addr:
				shared[name] = true
			}
		}
	}
	return shared
}

// sameIPAddress compares two addresses, so an IPv6 address written
// differently ("2001:DB8:0::1" vs "2001:db8::1") still matches.
func sameIPAddress(a, b string) bool {
	if a == b {
		return true
	}
	ipA, errA := netip.ParseAddr(a)
	ipB, errB := netip.ParseAddr(b)
	return errA == nil && errB == nil && ipA == ipB
}

// nmapSelection is what a host's Import Nmap takes from a file.
type nmapSelection struct {
	hosts  []nmapHost // the entries whose ports are imported
	listed bool       // the file has an entry for the host (address or hostname)
	state  string     // that entry's status when listed: "up", "down", ...
}

// nmapHostRule ends every per-host selection error.
const nmapHostRule = "A host's Import Nmap only imports the scan entry whose IP address or hostname is the host's identifier " +
	"(or, for a host named any other way, the one host of a single-target scan), so another machine's ports are never merged into it. " +
	"Import scans of other or several hosts with Import Nmap on the assessment overview."

// nmapHostsFor picks the <host> entries of a per-host upload that belong to
// the host with the given identifier, so another machine's ports are never
// merged into it:
//   - Entries whose IP address or hostname is the identifier (see matches)
//     decide alone, whatever their state: the ones nmap saw up are imported,
//     and if it saw none of them up (e.g. -v lists the host as down) nothing
//     is. If some of them were seen (see seen), only those are imported, so
//     in a -Pn scan an address that a stale PTR record or --resolve-all gives
//     the same name, and that has no open port, never gets in the way. An
//     entry nmap scanned as the identifier (see scannedAs) is only set aside
//     that way for another one scanned as it, though: if the seen entries
//     only have the name as a PTR record, the entries scanned as it count as
//     seen too. A hostname that several seen addresses share (an HA pair, a
//     reassigned address, --resolve-all) can't tell which machine the host
//     is, which is an error.
//   - Otherwise an identifier that is an IP address is not in the file, which
//     is an error unless nmap saw no host up at all.
//   - Any other identifier (a name, a CIDR range) can't be compared with the
//     file, so only the one host of a single-target scan is imported (for a
//     CIDR range, only if it lies inside it); several targets are an error.
func nmapHostsFor(run nmapRun, identifier string) (nmapSelection, error) {
	var sel nmapSelection
	var up, seen []nmapHost // seen: the matching entries nmap saw (see seen)
	targetSeen := false     // one of them was scanned as the identifier
	for _, nh := range run.Hosts {
		if nh.matches(identifier) {
			if !sel.listed || nh.up() {
				sel.state = nh.state()
			}
			sel.listed = true
			if nh.up() {
				sel.hosts = append(sel.hosts, nh)
			}
			if nh.seen() {
				seen = append(seen, nh)
				targetSeen = targetSeen || nh.scannedAs(identifier)
			}
		}
		if nh.up() {
			up = append(up, nh)
		}
	}
	if len(seen) > 0 && !targetSeen {
		// -Pn lists the address nmap resolved a target name to up even when
		// it shows no open port: it still counts, so an entry that only has
		// the name as a (possibly stale) PTR record can't take its place.
		seen = nil
		for _, nh := range sel.hosts { // the matching up entries, in file order
			if nh.seen() || nh.scannedAs(identifier) {
				seen = append(seen, nh)
			}
		}
	}
	if _, err := netip.ParseAddr(identifier); err != nil && nmapMachines(seen) > 1 {
		return nmapSelection{}, &nmapFileError{fmt.Sprintf(
			"%s is the hostname of several addresses in this file (%s), so it is not clear which machine this host is; "+
				"set its identifier to one of these addresses. %s", identifier, nmapHostNames(seen), nmapHostRule)}
	}
	if len(seen) > 0 {
		sel.hosts = seen
	}
	if sel.listed || len(up) == 0 {
		return sel, nil
	}

	if _, err := netip.ParseAddr(identifier); err == nil {
		return nmapSelection{}, &nmapFileError{fmt.Sprintf(
			"%s is not in this file (hosts up: %s). %s", identifier, nmapHostNames(up), nmapHostRule)}
	}
	if !nmapSingleTarget(run) {
		return nmapSelection{}, &nmapFileError{fmt.Sprintf(
			"%s is not in this file, which covers several targets (hosts up: %s). %s", identifier, nmapHostNames(up), nmapHostRule)}
	}
	if prefix, err := netip.ParsePrefix(identifier); err == nil && !up[0].inPrefix(prefix) {
		return nmapSelection{}, &nmapFileError{fmt.Sprintf(
			"this file's only host, %s, is outside %s. %s", up[0].name(), identifier, nmapHostRule)}
	}
	return nmapSelection{hosts: up}, nil
}

// nmapSingleTarget reports whether the file describes one machine: every
// entry has the same address and the run statistics, when present, count
// at most one target. A non-verbose scan of a range lists only the hosts
// that were up, so only the statistics show that it covered more.
func nmapSingleTarget(run nmapRun) bool {
	if run.targets() > 1 {
		return false
	}
	for _, nh := range run.Hosts {
		if nh.key() != run.Hosts[0].key() {
			return false
		}
	}
	return true
}

// nmapPortKey returns the number and protocol a scanned port is stored
// under, or ok=false when either is outside what AddPort accepts (1-65535,
// or 0-255 for protocol ip, the IP protocol numbers -sO reports). Nmap
// never writes other values, but hand-edited or converted files can, and an
// unchecked uint16 conversion would wrap portid 65616 onto port 80 (the
// explicit bounds keep that conversion visibly safe).
func nmapPortKey(np nmapPort) (number uint16, protocol string, ok bool) {
	protocol = strings.ToLower(np.Protocol)
	if np.PortID < 0 || np.PortID > 65535 || !validPortProtocol(protocol) || !validPortNumber(np.PortID, protocol) {
		return 0, "", false
	}
	return uint16(np.PortID), protocol, true
}

// nmapServiceInfo joins the service's product, version and extra info into
// the string stored in Port.Info ("" when the scan ran without -sV).
func nmapServiceInfo(np nmapPort) string {
	var parts []string
	for _, s := range []string{np.Service.Product, np.Service.Version, np.Service.ExtraInfo} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// nmapExactVersion reports whether a scanned version names one release:
// not empty or "unknown", and not a range ("3.X - 4.X", "8.3.0 - 8.3.7"),
// a wildcard ("2.6.X") or a lower bound ("9.6.0 or later").
func nmapExactVersion(version string) bool {
	parts := strings.FieldsFunc(strings.ToLower(version), func(r rune) bool { return r == ' ' || r == '.' })
	for _, part := range parts {
		switch part {
		case "x", "-", "or", "unknown":
			return false
		}
	}
	return len(parts) > 0
}

// lessDetailed reports whether a scan result tells less about the port's
// software than the stored Info does: it names no product, or it names the
// product the stored Info starts with but no exact version (see
// nmapExactVersion), or it is only the start of the stored Info. So
// "unauthorized", "MySQL unauthorized", "Samba smbd 3.X - 4.X" and
// "OpenSSH 8.2p1" are less detailed than "MySQL 8.0.36", "Samba smbd
// 4.6.2" and "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5", while "OpenSSH 9.6p1" (a
// new version) and "nginx" (another product) are not.
func lessDetailed(stored string, np nmapPort) bool {
	product := np.Service.Product
	if product == "" {
		return true
	}
	return strings.HasPrefix(stored, product+" ") &&
		(!nmapExactVersion(np.Service.Version) || strings.HasPrefix(stored, nmapServiceInfo(np)+" "))
}

// scriptEntry is one NSE result in Port.ScriptOutput (a JSON array).
type scriptEntry struct {
	ID     string `json:"id"`
	Output string `json:"output"`
}

// nseFailed reports whether an NSE output is nmap's report that the script
// failed ("ERROR: Script execution failed (use -d to debug)").
func nseFailed(output string) bool {
	return strings.HasPrefix(strings.TrimSpace(output), "ERROR:")
}

// mergeScriptOutput merges a scan's NSE results into a port's stored
// ScriptOutput by script id: a new output replaces the entry with the same
// id (an empty one never blanks it, and a failed run never replaces an
// earlier result), new ids are appended in scan order and ids the scan did
// not run are kept. It reports whether anything changed.
func mergeScriptOutput(stored string, scripts []nmapScript) (string, bool) {
	if len(scripts) == 0 {
		return stored, false
	}
	var entries []scriptEntry
	if stored != "" && json.Unmarshal([]byte(stored), &entries) != nil {
		entries = nil // unreadable, so the UI can't show it either: start over
	}
	index := make(map[string]int, len(entries))
	for i, e := range entries {
		index[e.ID] = i
	}

	changed := false
	for _, s := range scripts {
		i, seen := index[s.ID]
		switch {
		case !seen:
			index[s.ID] = len(entries)
			entries = append(entries, scriptEntry(s))
			changed = true
		case s.Output == "" || s.Output == entries[i].Output:
		case nseFailed(s.Output) && entries[i].Output != "":
			// keep the earlier result rather than nmap's error message
		default:
			entries[i].Output = s.Output
			changed = true
		}
	}
	if !changed {
		return stored, false
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return stored, false
	}
	return string(b), true
}

// weakServiceName reports whether a scanned service name says nothing about
// what runs on the port: "tcpwrapped" (the connection closed before any
// data came back) or "unknown".
func weakServiceName(name string) bool {
	return strings.EqualFold(name, "tcpwrapped") || strings.EqualFold(name, "unknown")
}

// mergeNmapPort folds one scanned port into p (a stored port, or a new one
// with only its key set). An import only adds information, so a less
// detailed scan (a -p- sweep, -sV without -sC, a failed probe) never erases
// or downgrades what an earlier scan or the user recorded:
//   - An empty Service or Info takes whatever the scan has.
//   - Otherwise Service only takes a name nmap probed (-sV): never a
//     port-table guess (method="table"), "tcpwrapped" or "unknown".
//   - Info takes a non-empty product/version string, unless the service
//     name stays and the result is less detailed than the stored Info (see
//     lessDetailed): "MySQL unauthorized" or "Samba smbd 3.X - 4.X" never
//     replaces "MySQL 8.0.36" or "Samba smbd 4.6.2".
//   - Info describes the service it was scanned with, so when a probe
//     replaces the stored Service with another name (ssh where http was)
//     but finds no product/version, the stored Info, which described the
//     old service, is cleared: a port never shows one service's name with
//     another's version.
//   - A Service or Info the user typed (ServiceEdited/InfoEdited) is kept;
//     kept reports that the scan would have changed it.
//   - NSE output is merged by script id (see mergeScriptOutput).
//
// changed reports whether p changed.
func mergeNmapPort(p *model.Port, np nmapPort) (changed, kept bool) {
	renamed := false // the probe replaced the stored Service with another name
	switch name := np.Service.Name; {
	case !hasValue(name) || name == p.Service:
	case !hasValue(p.Service):
		p.Service, p.ServiceEdited = name, false
		changed = true
	case np.Service.Method != "probed" || weakServiceName(name):
		// a guess or an inconclusive probe never replaces a known name
	case p.ServiceEdited:
		kept = true
	default:
		renamed = !strings.EqualFold(name, p.Service)
		p.Service = name
		changed = true
	}

	switch info := nmapServiceInfo(np); {
	case info == p.Info:
	case info == "":
		if renamed && hasValue(p.Info) { // the old service's version
			if p.InfoEdited {
				kept = true
			} else {
				p.Info = ""
				changed = true
			}
		}
	case !hasValue(p.Info):
		p.Info, p.InfoEdited = info, false
		changed = true
	case !renamed && lessDetailed(p.Info, np):
		// the same service, scanned in less detail: keep the details
	case p.InfoEdited:
		kept = true
	default:
		p.Info = info
		changed = true
	}

	if out, ok := mergeScriptOutput(p.ScriptOutput, np.Scripts); ok {
		p.ScriptOutput = out
		changed = true
	}
	return changed, kept
}

// portChanges lists the columns of a stored port an import changed, so
// the update writes only those and never a stale copy of the others.
func portChanges(before, after model.Port) map[string]interface{} {
	cols := map[string]interface{}{}
	if after.Service != before.Service {
		cols["service"] = after.Service
	}
	if after.Info != before.Info {
		cols["info"] = after.Info
	}
	if after.ScriptOutput != before.ScriptOutput {
		cols["script_output"] = after.ScriptOutput
	}
	if after.ServiceEdited != before.ServiceEdited {
		cols["service_edited"] = after.ServiceEdited
	}
	if after.InfoEdited != before.InfoEdited {
		cols["info_edited"] = after.InfoEdited
	}
	return cols
}

// nmapImportStats counts what an import did to a host's ports.
type nmapImportStats struct {
	Added   int // ports created
	Updated int // existing ports whose data changed
	Skipped int // open ports with an invalid number or protocol
	Kept    int // ports where a Service/Info the user typed was kept over another scanned value
}

func (s *nmapImportStats) add(o nmapImportStats) {
	s.Added += o.Added
	s.Updated += o.Updated
	s.Skipped += o.Skipped
	s.Kept += o.Kept
}

// -------------------------------------------------------------------
// upsertPortsInTx – merges a slice of nmapPort records into a single
// host's ports inside an existing transaction (see nmapImportStats for
// what it counts).
// -------------------------------------------------------------------
func upsertPortsInTx(tx *gorm.DB, hid uuid.UUID, ports []nmapPort) (nmapImportStats, error) {
	var st nmapImportStats
	for _, np := range ports {
		if np.State.State != "open" {
			continue
		}

		portNum, proto, ok := nmapPortKey(np)
		if !ok {
			st.Skipped++
			continue
		}

		var existing model.Port
		err := tx.Where("host_id = ? AND number = ? AND protocol = ?", hid, portNum, proto).
			First(&existing).Error
		if err == nil {
			merged := existing
			changed, kept := mergeNmapPort(&merged, np)
			if kept {
				st.Kept++
			}
			if changed {
				if err := tx.Model(&existing).Updates(portChanges(existing, merged)).Error; err != nil {
					return st, err
				}
				st.Updated++
			}
			continue
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return st, err
		}

		port := model.Port{
			ID:       uuid.New(),
			HostID:   hid,
			Number:   portNum,
			Protocol: proto,
		}
		mergeNmapPort(&port, np)
		if err := tx.Create(&port).Error; err != nil {
			return st, err
		}
		st.Added++
	}
	return st, nil
}

// nmapImportResult is what a host's Import Nmap did: the port counts, the
// file hosts the ports came from, and how the file lists the host itself
// (State is "" when it doesn't).
type nmapImportResult struct {
	nmapImportStats
	ImportedFrom []string
	State        string
}

// -------------------------------------------------------------------
// ImportNmapXML – shared function to parse nmap XML and merge the ports
// of the matching <host> into a single known host (see nmapHostsFor).
// Problems with the file itself come back as *nmapFileError, anything
// else is a database error.
// -------------------------------------------------------------------
func ImportNmapXML(db *storage.DB, host *model.Host, xmlData []byte) (nmapImportResult, error) {
	res := nmapImportResult{ImportedFrom: []string{}}
	run, err := parseNmapXML(xmlData)
	if err != nil {
		return res, err
	}
	sel, err := nmapHostsFor(run, host.Identifier)
	if err != nil {
		return res, err
	}
	res.State = sel.state
	seen := map[string]bool{}
	for _, nh := range sel.hosts {
		if k := nh.key(); !seen[k] {
			seen[k] = true
			res.ImportedFrom = append(res.ImportedFrom, nh.name())
		}
	}

	txErr := db.Transaction(func(tx *gorm.DB) error {
		for _, nh := range sel.hosts {
			st, err := upsertPortsInTx(tx, host.ID, nh.Ports)
			if err != nil {
				return err
			}
			res.add(st)
		}
		return nil
	})
	return res, txErr
}

// findNmapHost returns the assessment host a bulk-imported entry belongs
// to, matched the way a host's own Import Nmap matches entries: the host's
// identifier is the entry's identifier or one of its IP addresses (IPv6
// compared by value), or else one of its hostnames (case-insensitive). A
// host whose identifier is an IP address only matches by address, and a
// hostname in shared (see nmapSharedNames) matches no host, so entries of
// two different addresses are never merged into one host. An entry that
// was not seen (see seen) only matches by address: its names may belong
// to the machine another entry shows.
func findNmapHost(hosts []model.Host, nh nmapHost, identifier string, shared map[string]bool) (model.Host, bool) {
	for _, h := range hosts {
		if h.Identifier == identifier || nh.matchesAddress(h.Identifier) {
			return h, true
		}
	}
	if !nh.seen() {
		return model.Host{}, false
	}
	for _, h := range hosts {
		if _, err := netip.ParseAddr(h.Identifier); err != nil &&
			!shared[strings.ToLower(h.Identifier)] && nh.matchesHostname(h.Identifier) {
			return h, true
		}
	}
	return model.Host{}, false
}

// -------------------------------------------------------------------
// BulkImportNmap – POST /assessments/:eid/nmap
// Parses a multi-host nmap XML, creates hosts by IP if they don't
// exist, and upserts ports for each host in a single transaction.
// -------------------------------------------------------------------
func BulkImportNmap(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		eid, err := uuid.Parse(c.Param("eid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assessment id"})
			return
		}

		if verifyAssessmentOwner(db, eid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
			return
		}

		fileHeader, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file not provided"})
			return
		}
		if fileHeader.Size > maxNmapUploadSize {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file too large (max 10 MB)"})
			return
		}

		f, err := fileHeader.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot open uploaded file"})
			return
		}
		defer f.Close()

		xmlBytes, err := io.ReadAll(io.LimitReader(f, maxNmapUploadSize+1))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot read file"})
			return
		}
		if int64(len(xmlBytes)) > maxNmapUploadSize {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file too large (max 10 MB)"})
			return
		}

		run, err := parseNmapXML(xmlBytes)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// hostsSkipped counts the <host> entries that were not imported.
		var hostsFound, hostsCreated, hostsSkipped int
		var ports nmapImportStats
		shared := nmapSharedNames(run.Hosts)
		txErr := db.Transaction(func(tx *gorm.DB) error {
			// The assessment's hosts, matched like a host's own Import Nmap
			// matches entries, so a re-import never duplicates a host that
			// was added under its hostname or another spelling of its IPv6.
			var hosts []model.Host
			if err := tx.Where("assessment_id = ?", eid).Order("created_at").Find(&hosts).Error; err != nil {
				return err
			}

			for _, nh := range run.Hosts {
				if !nh.up() {
					hostsSkipped++
					continue // down/unknown entries from -v or -sL scans
				}

				identifier := nh.bulkIdentifier()
				if identifier == "" || !hostIdentifierRe.MatchString(identifier) {
					hostsSkipped++
					continue // no usable address
				}

				host, found := findNmapHost(hosts, nh, identifier, shared)
				if !found {
					// -Pn makes nmap report every target up (reason
					// "user-set"), so only create those with a port to import.
					if !nh.seen() {
						_, invalid := nh.openPorts()
						hostsSkipped++
						ports.Skipped += invalid
						continue
					}

					// Pick hostname as label if available
					label := ""
					if len(nh.Hostnames) > 0 {
						label = nh.Hostnames[0].Name
					}
					host = model.Host{
						ID:           uuid.New(),
						AssessmentID: eid,
						Identifier:   identifier,
						Label:        label,
					}
					if err := tx.Create(&host).Error; err != nil {
						return err
					}
					hosts = append(hosts, host)
					hostsCreated++
				}
				hostsFound++

				st, err := upsertPortsInTx(tx, host.ID, nh.Ports)
				if err != nil {
					return err
				}
				ports.add(st)
			}
			return nil
		})
		if txErr != nil {
			log.Printf("BulkImportNmap error: %v", txErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to import nmap results"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{
			"hosts_found":   hostsFound,
			"hosts_created": hostsCreated,
			"hosts_skipped": hostsSkipped,
			"ports_added":   ports.Added,
			"ports_updated": ports.Updated,
			"skipped":       ports.Skipped,
			"kept":          ports.Kept,
		})
	}
}

// -------------------------------------------------------------------
// ImportNmap – POST /hosts/:hid/nmap
// Expects multipart/form-data with a file field named "file".
// Inserts or updates ports inside a single transaction.
// -------------------------------------------------------------------
func ImportNmap(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		importHost := verifyHostOwner(db, hid, userID)
		if importHost == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		fileHeader, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file not provided"})
			return
		}
		if fileHeader.Size > maxNmapUploadSize {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file too large (max 10 MB)"})
			return
		}

		f, err := fileHeader.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot open uploaded file"})
			return
		}
		defer f.Close()

		xmlBytes, err := io.ReadAll(io.LimitReader(f, maxNmapUploadSize+1))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot read file"})
			return
		}
		if int64(len(xmlBytes)) > maxNmapUploadSize {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file too large (max 10 MB)"})
			return
		}

		res, importErr := ImportNmapXML(db, importHost, xmlBytes)
		var fileErr *nmapFileError
		if errors.As(importErr, &fileErr) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fileErr.Error()})
			return
		}
		if importErr != nil {
			log.Printf("ImportNmap error: %v", importErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to import ports"})
			return
		}
		go RecordActivity(db, importHost.AssessmentID, userID, "nmap_import",
			fmt.Sprintf("Nmap XML import on %s: +%d ports, ~%d updated", importHost.Identifier, res.Added, res.Updated))
		c.JSON(http.StatusCreated, gin.H{
			"added":   res.Added,
			"updated": res.Updated,
			"skipped": res.Skipped,
			"kept":    res.Kept,
			// The file hosts whose ports were imported ([] when none), and
			// the state the file lists this host in: "" when the file does
			// not list it, so imported_from is the one host of a
			// single-target scan (or empty if nmap saw no host up).
			"imported_from": res.ImportedFrom,
			"host_state":    res.State,
		})
	}
}

// -------------------------------------------------------------------
// UpdateHost – PUT /hosts/:hid
// -------------------------------------------------------------------
func UpdateHost(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		host := verifyHostOwner(db, hid, userID)
		if host == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var payload struct {
			Identifier string `json:"identifier"`
			Label      string `json:"label"`
			DeviceType string `json:"device_type"`
			OS         string `json:"os"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Identifier is the host's key — require it so a partial update can't
		// blank it (map-based Updates writes zero values for every field).
		if payload.Identifier == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "identifier is required"})
			return
		}
		if !validHostIdentifier(payload.Identifier) {
			c.JSON(http.StatusBadRequest, gin.H{"error": identifierErrMsg})
			return
		}

		result := db.Model(&model.Host{}).
			Where("id = ?", hid).
			Updates(map[string]interface{}{
				"identifier":  payload.Identifier,
				"label":       payload.Label,
				"device_type": payload.DeviceType,
				"os":          payload.OS,
			})

		if result.Error != nil {
			log.Printf("UpdateHost DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update host"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}

// -------------------------------------------------------------------
// DeleteHost – DELETE /hosts/:hid
// Removes the host and all dependent records via CASCADE.
// -------------------------------------------------------------------
func DeleteHost(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		host := verifyHostOwner(db, hid, userID)
		if host == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		if err := db.Delete(&model.Host{}, "id = ?", hid).Error; err != nil {
			log.Printf("DeleteHost DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete host"})
			return
		}
		go RecordActivity(db, host.AssessmentID, userID, "host_deleted", "Deleted host "+host.Identifier)
		c.Status(http.StatusNoContent)
	}
}

// portEdit is the body of PUT /hosts/:hid/ports/:pid. Every field is
// optional: one left out (or null) keeps its stored value. A Service or
// Info the edit changes becomes the user's (service_edited/info_edited),
// so Nmap imports keep it; sending service_edited or info_edited sets or
// clears that mark directly (false lets imports update the field again).
type portEdit struct {
	Number        *uint16 `json:"number"`
	Protocol      *string `json:"protocol"`
	Service       *string `json:"service"`
	Info          *string `json:"info"`
	ServiceEdited *bool   `json:"service_edited"`
	InfoEdited    *bool   `json:"info_edited"`
}

var errNothingToUpdate = errors.New("nothing to update")

// changes returns the columns the edit sets on the stored port p.
func (e portEdit) changes(p model.Port) (map[string]interface{}, error) {
	if e == (portEdit{}) {
		return nil, errNothingToUpdate
	}
	cols := map[string]interface{}{}
	number, protocol := int(p.Number), p.Protocol
	if e.Protocol != nil {
		if !validPortProtocol(*e.Protocol) {
			return nil, errors.New("protocol must be tcp, udp, sctp, or ip")
		}
		protocol = *e.Protocol
		cols["protocol"] = protocol
	}
	if e.Number != nil {
		number = int(*e.Number)
		cols["number"] = *e.Number
	}
	if (e.Number != nil || e.Protocol != nil) && !validPortNumber(number, protocol) {
		return nil, errPortNumber
	}
	editPortField(cols, "service", p.Service, p.ServiceEdited, e.Service, e.ServiceEdited)
	editPortField(cols, "info", p.Info, p.InfoEdited, e.Info, e.InfoEdited)
	return cols, nil
}

// editPortField adds an edit of the Service or Info column to cols. value
// is the new text and mark the explicit <column>_edited flag (nil: not
// sent). Changing the text (surrounding whitespace aside, since the edit
// modal trims) marks it as the user's, so saving a port unchanged leaves
// the mark alone; only a non-empty value can be marked.
func editPortField(cols map[string]interface{}, column, stored string, storedMark bool, value *string, mark *bool) {
	if value == nil && mark == nil {
		return
	}
	text, edited := stored, storedMark
	if value != nil {
		text = *value
		cols[column] = text
		if strings.TrimSpace(text) != strings.TrimSpace(stored) {
			edited = true
		}
	}
	if mark != nil {
		edited = *mark
	}
	cols[column+"_edited"] = edited && hasValue(text)
}

// -------------------------------------------------------------------
// UpdatePort – PUT /hosts/:hid/ports/:pid
// -------------------------------------------------------------------
func UpdatePort(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hostID, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		portID, err := uuid.Parse(c.Param("pid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid port id"})
			return
		}

		if verifyHostOwner(db, hostID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var payload portEdit
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if payload == (portEdit{}) {
			c.JSON(http.StatusBadRequest, gin.H{"error": errNothingToUpdate.Error()})
			return
		}

		// The stored port: omitted fields keep its values, and the edit is
		// compared with it to tell which fields the user changed.
		var existing model.Port
		if err := db.Where("id = ? AND host_id = ?", portID, hostID).First(&existing).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "port not found"})
				return
			}
			log.Printf("UpdatePort DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update port"})
			return
		}

		// Validated like AddPort, so an update can't set an invalid/blank
		// protocol or a number out of its range (0-255 for ip).
		cols, err := payload.changes(existing)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result := db.Model(&model.Port{}).
			Where("id = ? AND host_id = ?", portID, hostID).
			Updates(cols)

		if result.Error != nil {
			log.Printf("UpdatePort DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update port"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "port not found"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}

// -------------------------------------------------------------------
// DeletePort – DELETE /hosts/:hid/ports/:pid
// -------------------------------------------------------------------
func DeletePort(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hostID, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		portID, err := uuid.Parse(c.Param("pid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid port id"})
			return
		}

		if verifyHostOwner(db, hostID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		result := db.Where("id = ? AND host_id = ?", portID, hostID).Delete(&model.Port{})
		if result.Error != nil {
			log.Printf("DeletePort DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete port"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "port not found"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}

// -------------------------------------------------------------------
// SetCompromised – PATCH /hosts/:hid/compromised
// Toggles the compromised flag on a host.
// -------------------------------------------------------------------
func SetCompromised(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		if verifyHostOwner(db, hid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var payload struct {
			Compromised bool `json:"compromised"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := db.Model(&model.Host{}).
			Where("id = ?", hid).
			Update("compromised", payload.Compromised).Error; err != nil {
			log.Printf("SetCompromised DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update host"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}
