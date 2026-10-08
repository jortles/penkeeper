package api

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxImportProblems caps how many problems an import rejection lists.
const maxImportProblems = 20

// nonInfrastructureTypes are assessment types penkeeper does not keep.
// Import skips assessments of these types, with their hosts.
var nonInfrastructureTypes = map[string]bool{
	"web_application":    true,
	"mobile_application": true,
	"hardware":           true,
}

// imported reports whether Import takes ea. Penkeeper keeps infrastructure
// assessments only: Import takes an assessment with no type (penkeeper writes
// none), the "infrastructure" type or an unknown type, and skips the types in
// nonInfrastructureTypes.
func (ea exportAssessment) imported() bool {
	return !nonInfrastructureTypes[ea.Type]
}

// legacyType reports whether ea has an unknown type. Hosts in such an
// assessment may have identifiers the strict rule rejects, so repair fixes
// them instead of letting them reject the whole bundle.
func (ea exportAssessment) legacyType() bool {
	return ea.Type != "" && ea.Type != "infrastructure" && !nonInfrastructureTypes[ea.Type]
}

// disallowedRunRe matches a run of characters hostIdentifierRe rejects.
var disallowedRunRe = regexp.MustCompile(`[^a-zA-Z0-9.\-:/]+`)

// repairIdentifier turns an identifier the strict rule rejects into one it
// accepts: a URL becomes its host name, and each run of other characters
// becomes "-". The result is unique among used (compared ignoring case,
// which used records), with "-2", "-3", ... added when needed, so every
// host stays reachable by its identifier.
func repairIdentifier(id string, used map[string]bool) string {
	if u, err := url.Parse(id); err == nil && u.Hostname() != "" {
		id = u.Hostname()
	}
	id = strings.Trim(disallowedRunRe.ReplaceAllString(id, "-"), "-")
	if id == "" {
		id = "host"
	}
	base := id
	for n := 2; ; n++ {
		if len(id) > 255 {
			id = id[:255]
		}
		if !used[strings.ToLower(id)] {
			used[strings.ToLower(id)] = true
			return id
		}
		suffix := "-" + strconv.Itoa(n)
		if len(base)+len(suffix) > 255 {
			base = base[:255-len(suffix)]
		}
		id = base + suffix
	}
}

// skipped returns one message per assessment Import skips, naming it and
// its type.
func (b exportBundle) skipped() []string {
	var skipped []string
	for i, ea := range b.Assessments {
		if !ea.imported() {
			skipped = append(skipped, fmt.Sprintf("assessment %d %q: type %q is not infrastructure", i+1, clip(ea.Name), clip(ea.Type)))
		}
	}
	return skipped
}

// validScriptOutput reports whether s is what the host page expects in
// Port.ScriptOutput: empty, or a JSON array of {id, output} objects.
func validScriptOutput(s string) bool {
	if s == "" {
		return true
	}
	var scripts []struct {
		ID     string `json:"id"`
		Output string `json:"output"`
	}
	return json.Unmarshal([]byte(s), &scripts) == nil && scripts != nil
}

// problemList collects messages, at most maxImportProblems, then a count of
// the rest.
type problemList struct {
	items []string
	more  int
}

func (l *problemList) add(format string, args ...interface{}) {
	if len(l.items) < maxImportProblems {
		l.items = append(l.items, fmt.Sprintf(format, args...))
	} else {
		l.more++
	}
}

func (l *problemList) list() []string {
	if l.more > 0 {
		return append(l.items, fmt.Sprintf("and %d more", l.more))
	}
	return l.items
}

// repair fixes, in place, values that older versions stored (through an
// import or an Nmap scan) but the API does not accept, so that bundles they
// exported can still be imported: an empty or too long name, a port with an
// invalid number or protocol (skipped) and NSE output that is not a JSON
// array (dropped). It returns a description of each change. Assessments
// Import skips are left alone.
func (b *exportBundle) repair() []string {
	var notes problemList
	for i := range b.Assessments {
		ea := &b.Assessments[i]
		if !ea.imported() {
			continue
		}
		where := fmt.Sprintf("assessment %d %q", i+1, clip(ea.Name))
		switch n := utf8.RuneCountInString(ea.Name); {
		case n == 0:
			ea.Name = "Untitled assessment"
			notes.add("%s: empty name imported as %q", where, ea.Name)
		case n > 200:
			ea.Name = string([]rune(ea.Name)[:200])
			notes.add("%s: name shortened to 200 characters", where)
		}
		var used map[string]bool
		if ea.legacyType() {
			used = map[string]bool{}
			for _, eh := range ea.Hosts {
				if validHostIdentifier(eh.Identifier) {
					used[strings.ToLower(eh.Identifier)] = true
				}
			}
		}
		for j := range ea.Hosts {
			eh := &ea.Hosts[j]
			hostWhere := fmt.Sprintf("%s, host %q", where, clip(eh.Identifier))
			if used != nil && !validHostIdentifier(eh.Identifier) {
				id := repairIdentifier(eh.Identifier, used)
				notes.add("%s: imported as %q, the original identifier is kept in the label", hostWhere, id)
				if eh.Label == "" {
					eh.Label = eh.Identifier
				} else {
					eh.Label = eh.Identifier + " — " + eh.Label
				}
				eh.Identifier = id
			}
			ports := eh.Ports[:0]
			for _, ep := range eh.Ports {
				portWhere := fmt.Sprintf("%s, port %d/%s", hostWhere, ep.Number, clip(ep.Protocol))
				if !validPortProtocol(ep.Protocol) {
					notes.add("%s: skipped, protocol must be tcp, udp, sctp or ip", portWhere)
					continue
				}
				if !validPortNumber(int(ep.Number), ep.Protocol) {
					notes.add("%s: skipped, %v", portWhere, errPortNumber)
					continue
				}
				if !validScriptOutput(ep.ScriptOutput) {
					ep.ScriptOutput = ""
					notes.add("%s: NSE script output dropped, it is not a JSON array of {id, output}", portWhere)
				}
				ports = append(ports, ep)
			}
			eh.Ports = ports
		}
	}
	return notes.list()
}

// validate checks what repair cannot fix: every host identifier must follow
// the rules that apply when the host is added through the API. It returns a
// description of each host that breaks them. Assessments Import skips are
// not checked.
func (b exportBundle) validate() []string {
	var problems problemList
	for i, ea := range b.Assessments {
		if !ea.imported() {
			continue
		}
		where := fmt.Sprintf("assessment %d %q", i+1, clip(ea.Name))
		for _, eh := range ea.Hosts {
			if !validHostIdentifier(eh.Identifier) {
				problems.add("%s, host %q: %s", where, clip(eh.Identifier), identifierErrMsg)
			}
		}
	}
	return problems.list()
}

// clip shortens s for an error message.
func clip(s string) string {
	const limit = 60
	if utf8.RuneCountInString(s) <= limit {
		return s
	}
	return string([]rune(s)[:limit]) + "…"
}
