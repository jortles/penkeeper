package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gin-gonic/gin/binding"
	"github.com/google/uuid"

	"penkeeper/internal/model"
)

// Realistic nmap -oX fixtures for one target (10.0.0.6) scanned three ways,
// a verbose subnet scan with down hosts, and a hand-edited file with values
// nmap itself never writes.
const (
	// nmap -sC -sV 10.0.0.6
	nmapRichXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sC -sV -oX rich.xml 10.0.0.6" start="1700000000" version="7.94" xmloutputversion="1.05">
<host starttime="1700000000" endtime="1700000100"><status state="up" reason="echo-reply" reason_ttl="63"/>
<address addr="10.0.0.6" addrtype="ipv4"/>
<hostnames></hostnames>
<ports><extraports state="closed" count="998"><extrareasons reason="reset" count="998"/></extraports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"/><script id="ssh-hostkey" output="&#xa;  3072 aa:bb:cc (RSA)&#xa;  256 dd:ee:ff (ECDSA)"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"/><script id="http-title" output="Site doesn&apos;t have a title (text/html)."/><script id="http-server-header" output="Apache/2.4.41 (Ubuntu)"/></port>
</ports>
</host>
<runstats><finished time="1700000100"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>`

	// nmap -p- -T4 10.0.0.6: names are port-table guesses, no versions or scripts.
	nmapSweepXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -p- -T4 -oX fast.xml 10.0.0.6" version="7.94" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply" reason_ttl="63"/>
<address addr="10.0.0.6" addrtype="ipv4"/>
<ports><extraports state="closed" count="65532"/>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="http" method="table" conf="3"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="http-proxy" method="table" conf="3"/></port>
</ports>
</host>
</nmaprun>`

	// nmap -sV -p22,80,8080 10.0.0.6: versions, no NSE scripts.
	nmapVersionXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -p22,80,8080 -oX sv.xml 10.0.0.6" version="7.94" xmloutputversion="1.05">
<host><status state="up" reason="echo-reply" reason_ttl="63"/>
<address addr="10.0.0.6" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu 4ubuntu0.5" extrainfo="Ubuntu Linux; protocol 2.0" ostype="Linux" method="probed" conf="10"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"/></port>
<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="63"/><service name="http" product="Jetty" version="9.4.z-SNAPSHOT" method="probed" conf="10"/></port>
</ports>
</host>
</nmaprun>`

	// nmap -v -sV 192.168.1.8-12: verbose output lists the down hosts too.
	nmapSubnetXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -v -sV -oX subnet.xml 192.168.1.8-12" version="7.94" xmloutputversion="1.05">
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.8" addrtype="ipv4"/>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.9" addrtype="ipv4"/>
</host>
<host><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.1.10" addrtype="ipv4"/>
<address addr="00:0C:29:AA:BB:10" addrtype="mac" vendor="VMware"/>
<hostnames><hostname name="web01.lab" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" product="OpenSSH" version="9.6p1" method="probed" conf="10"/></port>
</ports>
</host>
<host><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.1.11" addrtype="ipv4"/>
<hostnames><hostname name="dc01.lab" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" product="Dropbear sshd" version="2019.78" method="probed" conf="10"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack" reason_ttl="128"/><service name="microsoft-ds" method="table" conf="3"/></port>
<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack" reason_ttl="128"/><service name="ms-wbt-server" method="table" conf="3"/></port>
</ports>
</host>
<host><status state="down" reason="no-response" reason_ttl="0"/>
<address addr="192.168.1.12" addrtype="ipv4"/>
</host>
<runstats><finished time="1700002100"/><hosts up="2" down="3" total="5"/></runstats>
</nmaprun>`

	// Hand-edited/merged file: out-of-range portids and protocols AddPort
	// rejects, plus the IP protocol numbers -sO writes (0-255).
	nmapBadPortsXML = `<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="10.0.0.6" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="65616"><state state="open"/><service name="evil" product="WRAPPED"/></port>
<port protocol="tcp" portid="70000"><state state="open"/><service name="big"/></port>
<port protocol="tcp" portid="0"><state state="open"/><service name="zero"/></port>
<port protocol="tcp" portid="-1"><state state="open"/><service name="neg"/></port>
<port protocol="ip" portid="0"><state state="open"/><service name="hopopt"/></port>
<port protocol="icmp" portid="8"><state state="open"/><service name="echo"/></port>
<port protocol="" portid="23"><state state="open"/><service name="telnet"/></port>
<port protocol="TCP" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="ip" portid="6"><state state="open"/><service name="tcp"/></port>
<port protocol="ip" portid="255"><state state="open"/><service name="reserved"/></port>
<port protocol="ip" portid="256"><state state="open"/><service name="not-an-ip-protocol"/></port>
<port protocol="tcp" portid="65535"><state state="open"/><service name="unknown"/></port>
<port protocol="tcp" portid="99999"><state state="closed"/><service name="closed-and-invalid"/></port>
</ports></host></nmaprun>`

	// nmap -sV 192.168.1.8-12 without -v: only the host that answered is
	// listed; the run statistics show the scan covered five targets.
	nmapOneUpXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX one.xml 192.168.1.8-12" version="7.94" xmloutputversion="1.05">
<host><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.1.11" addrtype="ipv4"/>
<hostnames><hostname name="dc01.lab" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="Dropbear sshd" version="2019.78" method="probed" conf="10"/></port></ports>
</host>
<runstats><finished time="1700003100"/><hosts up="1" down="4" total="5"/></runstats>
</nmaprun>`

	// nmap -v -sV 10.10.10.40 10.10.10.41: the first target was down.
	nmapTargetDownXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -v -sV 10.10.10.40 10.10.10.41" version="7.94" xmloutputversion="1.05">
<host><status state="down" reason="no-response"/><address addr="10.10.10.40" addrtype="ipv4"/></host>
<host><status state="up" reason="echo-reply"/><address addr="10.10.10.41" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds" product="Samba smbd" method="probed" conf="10"/></port></ports></host>
<runstats><finished time="1700004100"/><hosts up="1" down="1" total="2"/></runstats>
</nmaprun>`

	// masscan -oX: one <host> entry (no <status>) per open port.
	nmapMasscanXML = `<?xml version="1.0"?>
<nmaprun scanner="masscan" version="1.0-BETA" xmloutputversion="1.03">
<host><address addr="10.0.0.30" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port></ports></host>
<host><address addr="10.0.0.30" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/></port></ports></host>
<runstats><finished time="1700000010"/><hosts up="2" down="0" total="2"/></runstats>
</nmaprun>`

	// nmap -Pn -sV 10.60.0.4-7: -Pn reports every target up ("user-set").
	// 10.60.0.6 has no open port but still has files01's PTR record (a
	// stale DHCP lease), and 10.60.0.7 only refused a connection.
	nmapPnStalePTRXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -Pn -sV -oX pn.xml 10.60.0.4-7" version="7.94" xmloutputversion="1.05">
<host><status state="up" reason="user-set" reason_ttl="0"/><address addr="10.60.0.4" addrtype="ipv4"/>
<ports><extraports state="filtered" count="1000"/></ports></host>
<host><status state="up" reason="user-set" reason_ttl="0"/><address addr="10.60.0.5" addrtype="ipv4"/>
<hostnames><hostname name="files01.corp.local" type="PTR"/></hostnames>
<ports><extraports state="filtered" count="998"/>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.6" method="probed" conf="10"/></port>
<port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="netbios-ssn" product="Samba smbd" version="4.6.2" method="probed" conf="10"/></port>
</ports></host>
<host><status state="up" reason="user-set" reason_ttl="0"/><address addr="10.60.0.6" addrtype="ipv4"/>
<hostnames><hostname name="files01.corp.local" type="PTR"/></hostnames>
<ports><extraports state="filtered" count="1000"/></ports></host>
<host><status state="up" reason="user-set" reason_ttl="0"/><address addr="10.60.0.7" addrtype="ipv4"/>
<hostnames><hostname name="Files01.Corp.Local" type="PTR"/></hostnames>
<ports><extraports state="filtered" count="999"/><port protocol="tcp" portid="22"><state state="closed" reason="reset"/><service name="ssh" method="table" conf="3"/></port></ports></host>
<runstats><finished time="1759900100"/><hosts up="4" down="0" total="4"/></runstats>
</nmaprun>`

	// nmap -Pn --resolve-all -sV app.lab: app.lab has two A records and
	// only 10.40.0.1 has an open port.
	nmapPnResolveAllXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -Pn --resolve-all -sV -oX app.xml app.lab" version="7.94" xmloutputversion="1.05">
<host><status state="up" reason="user-set"/><address addr="10.40.0.1" addrtype="ipv4"/>
<hostnames><hostname name="app.lab" type="user"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="http" product="nginx" tunnel="ssl" method="probed" conf="10"/></port></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.40.0.2" addrtype="ipv4"/>
<hostnames><hostname name="app.lab" type="user"/></hostnames>
<ports><extraports state="filtered" count="1000"/></ports></host>
<runstats><finished time="1759900100"/><hosts up="2" down="0" total="2"/></runstats>
</nmaprun>`

	// nmap -Pn -sV app.lab 10.40.0.5: app.lab resolved to 10.40.0.1, which
	// has no open port, and 10.40.0.5 is another machine whose stale PTR
	// record still says app.lab.
	nmapPnTargetStalePTRXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -Pn -sV -oX u3.xml app.lab 10.40.0.5" version="7.94" xmloutputversion="1.05">
<host><status state="up" reason="user-set"/><address addr="10.40.0.1" addrtype="ipv4"/>
<hostnames><hostname name="app.lab" type="user"/><hostname name="app.lab" type="PTR"/></hostnames>
<ports><extraports state="filtered" count="998"/>
<port protocol="tcp" portid="22"><state state="closed" reason="reset"/><service name="ssh" method="table" conf="3"/></port>
<port protocol="tcp" portid="80"><state state="closed" reason="reset"/><service name="http" method="table" conf="3"/></port>
</ports></host>
<host><status state="up" reason="user-set"/><address addr="10.40.0.5" addrtype="ipv4"/>
<hostnames><hostname name="app.lab" type="PTR"/></hostnames>
<ports><extraports state="filtered" count="998"/>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="7.4" extrainfo="protocol 2.0" method="probed" conf="10"/></port>
<port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/><service name="ms-wbt-server" product="Microsoft Terminal Services" method="probed" conf="10"/></port>
</ports></host>
<runstats><finished time="1759900100"/><hosts up="2" down="0" total="2"/></runstats>
</nmaprun>`
)

func mustParseNmap(t *testing.T, data string) nmapRun {
	t.Helper()
	run, err := parseNmapXML([]byte(data))
	if err != nil {
		t.Fatalf("parseNmapXML: %v", err)
	}
	return run
}

func TestParseNmapXML(t *testing.T) {
	run := mustParseNmap(t, nmapRichXML)
	if len(run.Hosts) != 1 || len(run.Hosts[0].Ports) != 2 {
		t.Fatalf("rich scan: got %d hosts, want 1 host with 2 ports", len(run.Hosts))
	}
	p := run.Hosts[0].Ports[1]
	if p.Service.Method != "probed" || len(p.Scripts) != 2 || run.Hosts[0].Status.State != "up" {
		t.Errorf("rich scan port 80 parsed as %+v (status %q)", p, run.Hosts[0].Status.State)
	}

	bad := []struct {
		name, data, wantMsg string
	}{
		{"not xml", "This is not XML at all\n", "contains no XML elements"},
		{"empty", "", "contains no XML elements"},
		{"nessus", `<?xml version="1.0" ?><NessusClientData_v2><Report name="scan"/></NessusClientData_v2>`, "expected element type <nmaprun> but have <NessusClientData_v2>"},
		{"truncated", nmapRichXML[:len(nmapRichXML)/2], "XML syntax error"},
		{"non-numeric portid", `<nmaprun><host><ports><port protocol="tcp" portid="ssh"/></ports></host></nmaprun>`, "invalid nmap XML"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNmapXML([]byte(tc.data))
			var fileErr *nmapFileError
			if !errors.As(err, &fileErr) {
				t.Fatalf("got %v (%T), want *nmapFileError", err, err)
			}
			if !strings.HasPrefix(err.Error(), "invalid nmap XML") || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("message %q, want it to contain %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestNmapHostUp(t *testing.T) {
	run := mustParseNmap(t, nmapSubnetXML)
	var up []string
	for _, h := range run.Hosts {
		if h.up() {
			up = append(up, h.Addresses[0].Addr)
		}
	}
	if fmt.Sprint(up) != "[192.168.1.10 192.168.1.11]" {
		t.Errorf("up hosts = %v, want only .10 and .11 (the down ones are skipped)", up)
	}

	others := mustParseNmap(t, `<nmaprun>
<host><address addr="10.0.0.1" addrtype="ipv4"/></host>
<host><status state="unknown" reason="list-scan"/><address addr="10.0.0.2" addrtype="ipv4"/></host>
<host><status state="skipped"/><address addr="10.0.0.3" addrtype="ipv4"/></host>
</nmaprun>`)
	if !others.Hosts[0].up() {
		t.Error("a host without <status> (hand-made file) should count as up")
	}
	if others.Hosts[1].up() || others.Hosts[2].up() {
		t.Error("unknown (-sL) and skipped hosts should not count as up")
	}
}

func TestNmapHostsFor(t *testing.T) {
	addrs := func(hosts []nmapHost) string {
		var s []string
		for _, h := range hosts {
			s = append(s, h.Addresses[0].Addr)
		}
		return strings.Join(s, ",")
	}

	cases := []struct {
		name, xml, identifier string
		// want: comma-separated addresses imported, or "error: <text the
		// message must contain>". state: how the file lists the host.
		want, state string
	}{
		{"single host, same address", nmapRichXML, "10.0.0.6", "10.0.0.6", "up"},
		{"single target, host added by name", nmapRichXML, "files01.corp.local", "10.0.0.6", ""},
		{"single target, another IP address", nmapRichXML, "10.0.0.7", "error: 10.0.0.7 is not in this file (hosts up: 10.0.0.6)", ""},
		{"single target inside a CIDR host", nmapRichXML, "10.0.0.0/24", "10.0.0.6", ""},
		{"single target outside a CIDR host", nmapRichXML, "10.1.0.0/16", "error: only host, 10.0.0.6, is outside 10.1.0.0/16", ""},
		{"multi-host, match by IPv4", nmapSubnetXML, "192.168.1.10", "192.168.1.10", "up"},
		{"multi-host, match by hostname", nmapSubnetXML, "dc01.lab", "192.168.1.11", "up"},
		{"multi-host, hostname case-insensitive", nmapSubnetXML, "DC01.Lab", "192.168.1.11", "up"},
		{"multi-host, IP not in the file", nmapSubnetXML, "192.168.1.50", "error: 192.168.1.50 is not in this file (hosts up: 192.168.1.10, 192.168.1.11)", ""},
		{"multi-host, the host is listed as down", nmapSubnetXML, "192.168.1.8", "", "down"},
		{"multi-host, name not in the file", nmapSubnetXML, "web01", "error: web01 is not in this file, which covers several targets", ""},
		{"multi-host, MAC address is not an identifier", nmapSubnetXML, "00:0C:29:AA:BB:10", "error: covers several targets", ""},
		{"host listed as down, the one other target up", nmapTargetDownXML, "10.10.10.40", "", "down"},
		{"name, the file's one up host among two targets", nmapTargetDownXML, "files01.corp.local", "error: covers several targets (hosts up: 10.10.10.41)", ""},
		{"non-verbose range scan, only another host up", nmapOneUpXML, "192.168.1.10", "error: 192.168.1.10 is not in this file (hosts up: 192.168.1.11)", ""},
		{"non-verbose range scan into a name", nmapOneUpXML, "files01.corp.local", "error: covers several targets", ""},
		{"non-verbose range scan, the host itself up", nmapOneUpXML, "192.168.1.11", "192.168.1.11", "up"},
		{"masscan entries for the host", nmapMasscanXML, "10.0.0.30", "10.0.0.30,10.0.0.30", "up"},
		{"masscan into a name (two targets per its stats)", nmapMasscanXML, "web30.lab", "error: covers several targets", ""},
		{"repeated entries of one address are one target", `<nmaprun>
<host><address addr="10.0.0.31"/><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
<host><address addr="10.0.0.31"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host>
</nmaprun>`, "web31.lab", "10.0.0.31,10.0.0.31", ""},
		// A name several machines share never merges them.
		{"hostname on two addresses (--resolve-all)", `<nmaprun>
<host><status state="up"/><address addr="10.40.0.1" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="user"/></hostnames></host>
<host><status state="up"/><address addr="10.40.0.2" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="user"/></hostnames></host>
<host><status state="up"/><address addr="10.40.0.3" addrtype="ipv4"/><hostnames><hostname name="other.lab" type="user"/></hostnames></host>
</nmaprun>`, "app.lab", "error: app.lab is the hostname of several addresses in this file (10.40.0.1, 10.40.0.2)", ""},
		{"PTR name shared by two addresses, case differs", `<nmaprun>
<host><status state="up"/><address addr="10.50.0.11" addrtype="ipv4"/><hostnames><hostname name="portal.lab" type="PTR"/></hostnames></host>
<host><status state="up"/><address addr="10.50.0.12" addrtype="ipv4"/><hostnames><hostname name="PORTAL.lab" type="PTR"/></hostnames></host>
</nmaprun>`, "Portal.Lab", "error: several addresses in this file (10.50.0.11, 10.50.0.12)", ""},
		{"shared name, only one of the addresses up", `<nmaprun>
<host><status state="down"/><address addr="10.50.0.11" addrtype="ipv4"/><hostnames><hostname name="portal.lab" type="PTR"/></hostnames></host>
<host><status state="up"/><address addr="10.50.0.12" addrtype="ipv4"/><hostnames><hostname name="portal.lab" type="PTR"/></hostnames></host>
</nmaprun>`, "portal.lab", "10.50.0.12", "up"},
		{"name on repeated entries of one address", `<nmaprun>
<host><address addr="10.0.0.31"/><hostnames><hostname name="web31.lab"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
<host><address addr="10.0.0.31"/><hostnames><hostname name="web31.lab"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host>
<host><address addr="10.0.0.32"/><hostnames><hostname name="web32.lab"/></hostnames></host>
</nmaprun>`, "web31.lab", "10.0.0.31,10.0.0.31", "up"},
		{"an IP address identifier only matches an address", `<nmaprun>
<host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/><hostnames><hostname name="10.0.0.5" type="user"/></hostnames></host>
<host><status state="up"/><address addr="10.0.0.10" addrtype="ipv4"/></host>
</nmaprun>`, "10.0.0.5", "error: 10.0.0.5 is not in this file (hosts up: 10.0.0.9, 10.0.0.10)", ""},
		// In a -Pn scan an address with no open port (a stale PTR
		// record, a dead --resolve-all address) never competes for a name.
		{"-Pn, the name's other addresses have no open port", nmapPnStalePTRXML, "files01.corp.local", "10.60.0.5", "up"},
		{"-Pn --resolve-all, one address has an open port", nmapPnResolveAllXML, "app.lab", "10.40.0.1", "up"},
		{"-Pn, the address with open ports", nmapPnStalePTRXML, "10.60.0.5", "10.60.0.5", "up"},
		{"-Pn, a host's own address with no open port", nmapPnStalePTRXML, "10.60.0.6", "10.60.0.6", "up"},
		{"-Pn, a name only on addresses with no open port", `<nmaprun>
<host><status state="up" reason="user-set"/><address addr="10.60.0.5" addrtype="ipv4"/><hostnames><hostname name="files01.corp.local" type="PTR"/></hostnames></host>
<host><status state="up" reason="user-set"/><address addr="10.60.0.6" addrtype="ipv4"/><hostnames><hostname name="files01.corp.local" type="PTR"/></hostnames></host>
</nmaprun>`, "files01.corp.local", "10.60.0.5,10.60.0.6", "up"},
		{"-Pn, a name on two addresses with open ports", `<nmaprun>
<host><status state="up" reason="user-set"/><address addr="10.60.0.5" addrtype="ipv4"/><hostnames><hostname name="files01.corp.local" type="PTR"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.60.0.6" addrtype="ipv4"/><hostnames><hostname name="files01.corp.local" type="PTR"/></hostnames><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.60.0.7" addrtype="ipv4"/><hostnames><hostname name="files01.corp.local" type="PTR"/></hostnames></host>
</nmaprun>`, "files01.corp.local", "error: several addresses in this file (10.60.0.5, 10.60.0.6)", ""},
		{"-Pn single-target scan into a name", `<nmaprun>
<host><status state="up" reason="user-set"/><address addr="10.60.0.9" addrtype="ipv4"/><hostnames><hostname name="nas.corp.local" type="PTR"/></hostnames><ports><port protocol="tcp" portid="445"><state state="open"/></port></ports></host>
<runstats><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>`, "fileserver", "10.60.0.9", ""},
		// The address a target name resolved to (hostname type
		// "user") still counts when -Pn shows no open port there, so another
		// machine that only has the name as a PTR record never replaces it.
		{"-Pn, the target name's address has no open port, a PTR-only one does", nmapPnTargetStalePTRXML, "app.lab", "error: app.lab is the hostname of several addresses in this file (10.40.0.1, 10.40.0.5)", ""},
		{"-Pn, the PTR-only address by its IP address", nmapPnTargetStalePTRXML, "10.40.0.5", "10.40.0.5", "up"},
		{"-Pn, the target name's address answers nothing", `<nmaprun>
<host><status state="up" reason="user-set"/><address addr="10.40.0.1" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="user"/></hostnames></host>
<host><status state="up" reason="user-set"/><address addr="10.40.0.2" addrtype="ipv4"/></host>
<host><status state="up" reason="user-set"/><address addr="10.40.0.5" addrtype="ipv4"/><hostnames><hostname name="APP.lab" type="PTR"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
</nmaprun>`, "app.lab", "error: several addresses in this file (10.40.0.1, 10.40.0.5)", ""},
		{"-Pn, only the target name's address, no open port", `<nmaprun>
<host><status state="up" reason="user-set"/><address addr="10.40.0.1" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="user"/></hostnames></host>
<host><status state="up" reason="user-set"/><address addr="10.40.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
</nmaprun>`, "app.lab", "10.40.0.1", "up"},
		{"-Pn --resolve-all, no address of the name has an open port", `<nmaprun>
<host><status state="up" reason="user-set"/><address addr="10.40.0.1" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="user"/></hostnames></host>
<host><status state="up" reason="user-set"/><address addr="10.40.0.2" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="user"/></hostnames></host>
</nmaprun>`, "app.lab", "10.40.0.1,10.40.0.2", "up"},
		{"-Pn --resolve-all, a dead address still gives way to a live one", `<nmaprun>
<host><status state="up" reason="user-set"/><address addr="10.40.0.1" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="user"/></hostnames><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.40.0.2" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="user"/></hostnames></host>
<host><status state="up" reason="user-set"/><address addr="10.40.0.5" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="PTR"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host>
</nmaprun>`, "app.lab", "error: several addresses in this file (10.40.0.1, 10.40.0.5)", ""},
		{"multi-host, hand-made file without addrtype", `<nmaprun>
<host><address addr="10.2.0.1"/></host>
<host><address addr="10.2.0.2"/></host>
</nmaprun>`, "10.2.0.2", "10.2.0.2", "up"},
		{"multi-host, IPv6 written differently", `<nmaprun>
<host><status state="up"/><address addr="2001:db8::10" addrtype="ipv6"/></host>
<host><status state="up"/><address addr="2001:db8::11" addrtype="ipv6"/></host>
</nmaprun>`, "2001:DB8:0::10", "2001:db8::10", "up"},
		{"no hosts at all", `<nmaprun scanner="nmap"></nmaprun>`, "10.0.0.6", "", ""},
		{"list scan (-sL): nothing up", `<nmaprun>
<host><status state="unknown" reason=""/><address addr="10.20.0.1" addrtype="ipv4"/></host>
<host><status state="unknown" reason=""/><address addr="10.20.0.2" addrtype="ipv4"/></host>
</nmaprun>`, "10.20.0.9", "", ""},
		{"list scan (-sL) listing the host", `<nmaprun>
<host><status state="unknown" reason=""/><address addr="10.20.0.1" addrtype="ipv4"/></host>
<host><status state="unknown" reason=""/><address addr="10.20.0.2" addrtype="ipv4"/></host>
</nmaprun>`, "10.20.0.2", "", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := nmapHostsFor(mustParseNmap(t, tc.xml), tc.identifier)
			if want, isErr := strings.CutPrefix(tc.want, "error: "); isErr {
				var fileErr *nmapFileError
				if !errors.As(err, &fileErr) {
					t.Fatalf("got hosts %q, err %v; want *nmapFileError", addrs(sel.hosts), err)
				}
				msg := err.Error()
				if !strings.Contains(msg, want) || !strings.Contains(msg, tc.identifier) ||
					!strings.Contains(msg, "another machine's ports are never merged") ||
					!strings.Contains(msg, "Import Nmap on the assessment overview") {
					t.Errorf("message %q, want it to contain %q, the identifier and the rule", msg, want)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if addrs(sel.hosts) != tc.want || sel.state != tc.state || sel.listed != (tc.state != "") {
				t.Errorf("imported hosts %q, state %q (listed %v); want %q, state %q",
					addrs(sel.hosts), sel.state, sel.listed, tc.want, tc.state)
			}
		})
	}
}

func TestNmapRunTargets(t *testing.T) {
	cases := map[string]int{
		nmapOneUpXML: 5,
		nmapRichXML:  1,
		nmapSweepXML: 0, // no <runstats>
		`<nmaprun><runstats><hosts total="many"/></runstats></nmaprun>`: 0, // ignored, the file still parses
	}
	for data, want := range cases {
		if got := mustParseNmap(t, data).targets(); got != want {
			t.Errorf("targets() = %d, want %d for %.80q", got, want, data)
		}
	}
}

func TestNmapHostNames(t *testing.T) {
	run := mustParseNmap(t, `<nmaprun>
<host><address addr="10.0.0.1"/></host><host><address addr="10.0.0.1"/></host>
<host><address addr="10.0.0.2"/></host><host><address addr="10.0.0.3"/></host>
<host><address addr="10.0.0.4"/></host><host><address addr="10.0.0.5"/></host>
<host><address addr="10.0.0.6"/></host><host><address addr="10.0.0.7"/></host>
<host><hostnames><hostname name="named.lab"/></hostnames></host>
</nmaprun>`)
	if got, want := nmapHostNames(run.Hosts), "10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5 and 3 more"; got != want {
		t.Errorf("nmapHostNames = %q, want %q", got, want)
	}
	if got := run.Hosts[len(run.Hosts)-1].name(); got != "named.lab" {
		t.Errorf("name of an entry with only a hostname = %q", got)
	}
}

func TestNmapPortKey(t *testing.T) {
	run := mustParseNmap(t, nmapBadPortsXML)
	var accepted, skipped []string
	for _, np := range run.Hosts[0].Ports {
		num, proto, ok := nmapPortKey(np)
		if ok {
			accepted = append(accepted, fmt.Sprintf("%d/%s", num, proto))
		} else {
			skipped = append(skipped, fmt.Sprintf("%d/%s", np.PortID, np.Protocol))
		}
	}
	if got, want := strings.Join(accepted, " "), "0/ip 22/tcp 6/ip 255/ip 65535/tcp"; got != want {
		t.Errorf("accepted %q, want %q", got, want)
	}
	if got, want := strings.Join(skipped, " "), "65616/tcp 70000/tcp 0/tcp -1/tcp 8/icmp 23/ 256/ip 99999/tcp"; got != want {
		t.Errorf("skipped %q, want %q", got, want)
	}
}

func TestValidPortNumber(t *testing.T) {
	cases := []struct {
		number   int
		protocol string
		want     bool
	}{
		{0, "ip", true}, {255, "ip", true}, {256, "ip", false}, {-1, "ip", false},
		{0, "tcp", false}, {1, "tcp", true}, {65535, "udp", true}, {65536, "sctp", false},
	}
	for _, tc := range cases {
		if got := validPortNumber(tc.number, tc.protocol); got != tc.want {
			t.Errorf("validPortNumber(%d, %q) = %v, want %v", tc.number, tc.protocol, got, tc.want)
		}
	}
}

// applyScan merges every open port of a parsed scan into ports, keyed like
// the ports table (number/protocol), as upsertPortsInTx does in the DB.
func applyScan(t *testing.T, ports map[string]*model.Port, data string) (added, updated, skipped int) {
	t.Helper()
	for _, h := range mustParseNmap(t, data).Hosts {
		for _, np := range h.Ports {
			if np.State.State != "open" {
				continue
			}
			num, proto, ok := nmapPortKey(np)
			if !ok {
				skipped++
				continue
			}
			key := fmt.Sprintf("%d/%s", num, proto)
			if p, exists := ports[key]; exists {
				if changed, _ := mergeNmapPort(p, np); changed {
					updated++
				}
				continue
			}
			p := &model.Port{Number: num, Protocol: proto}
			mergeNmapPort(p, np)
			ports[key] = p
			added++
		}
	}
	return added, updated, skipped
}

func scriptIDs(t *testing.T, p *model.Port) string {
	t.Helper()
	var entries []scriptEntry
	if p.ScriptOutput != "" {
		if err := json.Unmarshal([]byte(p.ScriptOutput), &entries); err != nil {
			t.Fatalf("script_output is not valid JSON: %v", err)
		}
	}
	var ids []string
	for _, e := range entries {
		ids = append(ids, e.ID+"="+e.Output)
	}
	return strings.Join(ids, " | ")
}

// The reported workflow: -sC -sV, then a -p- sweep, then -sV only. Nothing
// the first scan found may be blanked by the less detailed ones.
func TestReimportKeepsEarlierScanData(t *testing.T) {
	ports := map[string]*model.Port{}
	if a, u, s := applyScan(t, ports, nmapRichXML); a != 2 || u != 0 || s != 0 {
		t.Fatalf("rich import: added %d, updated %d, skipped %d", a, u, s)
	}
	rich22, rich80 := *ports["22/tcp"], *ports["80/tcp"]

	// -p- sweep: adds 8080, and leaves 22 and 80 exactly as they were.
	if a, u, _ := applyScan(t, ports, nmapSweepXML); a != 1 || u != 0 {
		t.Errorf("sweep import: added %d, updated %d; want 1 added, 0 updated", a, u)
	}
	if *ports["22/tcp"] != rich22 || *ports["80/tcp"] != rich80 {
		t.Errorf("sweep changed existing ports:\n22: %+v\n80: %+v", *ports["22/tcp"], *ports["80/tcp"])
	}
	if p := ports["8080/tcp"]; p.Service != "http-proxy" || p.Info != "" {
		t.Errorf("8080 after sweep: %+v", *p)
	}

	// -sV only: fills 8080's version and probed name, keeps 22/80 scripts.
	if a, u, _ := applyScan(t, ports, nmapVersionXML); a != 0 || u != 1 {
		t.Errorf("-sV import: added %d, updated %d; want 0 added, 1 updated (8080)", a, u)
	}
	if got := ports["80/tcp"]; got.Info != "Apache httpd 2.4.41 (Ubuntu)" || got.ScriptOutput != rich80.ScriptOutput {
		t.Errorf("80 after -sV: %+v", *got)
	}
	if got := scriptIDs(t, ports["22/tcp"]); !strings.HasPrefix(got, "ssh-hostkey=") {
		t.Errorf("22 scripts after -sV: %q", got)
	}
	if p := ports["8080/tcp"]; p.Service != "http" || p.Info != "Jetty 9.4.z-SNAPSHOT" {
		t.Errorf("8080 after -sV: service %q info %q; want the probed http / Jetty", p.Service, p.Info)
	}
}

func nmapPortFixture(name, method, product, version string, scripts ...nmapScript) nmapPort {
	var np nmapPort
	np.Protocol, np.PortID, np.State.State = "tcp", 80, "open"
	np.Service.Name, np.Service.Method = name, method
	np.Service.Product, np.Service.Version = product, version
	np.Scripts = scripts
	return np
}

func TestMergeNmapPort(t *testing.T) {
	stored := func() model.Port {
		return model.Port{
			Number: 80, Protocol: "tcp", Service: "http", Info: "Apache httpd 2.4.41",
			ScriptOutput: `[{"id":"http-title","output":"Login"},{"id":"http-server-header","output":"Apache/2.4.41"}]`,
		}
	}

	t.Run("blank incoming keeps everything", func(t *testing.T) {
		p := stored()
		if changed, kept := mergeNmapPort(&p, nmapPortFixture("", "", "", "")); changed || kept || p != stored() {
			t.Errorf("empty scan result changed the port: %+v", p)
		}
	})

	t.Run("table guess never replaces a name", func(t *testing.T) {
		p := stored()
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("http-alt", "table", "", "")); changed || p.Service != "http" {
			t.Errorf("service = %q, want http kept", p.Service)
		}
	})

	t.Run("table guess fills an empty name", func(t *testing.T) {
		p := model.Port{Number: 8080, Protocol: "tcp"}
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("http-proxy", "table", "", "")); !changed || p.Service != "http-proxy" {
			t.Errorf("service = %q, want http-proxy", p.Service)
		}
	})

	// Info describes the service it was scanned with.
	t.Run("probed name replaces, and clears the old service's info", func(t *testing.T) {
		p := stored()
		changed, kept := mergeNmapPort(&p, nmapPortFixture("ssh", "probed", "", ""))
		if !changed || kept || p.Service != "ssh" || p.Info != "" || p.ScriptOutput != stored().ScriptOutput {
			t.Errorf("changed=%v kept=%v port %+v; want ssh with no Info (the probe found no version)", changed, kept, p)
		}
	})

	t.Run("probed name replaces, with the new service's info", func(t *testing.T) {
		p := stored()
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("https", "probed", "Apache httpd", "")); !changed ||
			p.Service != "https" || p.Info != "Apache httpd" {
			t.Errorf("port %+v; want https with the scanned Apache httpd", p)
		}
	})

	t.Run("a typed info is kept when the service is renamed", func(t *testing.T) {
		p := stored()
		p.Info, p.InfoEdited = "Apache 2.4.41 - CVE-2021-41773 confirmed", true
		changed, kept := mergeNmapPort(&p, nmapPortFixture("ssh", "probed", "", ""))
		if !changed || !kept || p.Service != "ssh" || p.Info != "Apache 2.4.41 - CVE-2021-41773 confirmed" || !p.InfoEdited {
			t.Errorf("changed=%v kept=%v port %+v; want the typed Info kept", changed, kept, p)
		}
	})

	t.Run("a name that only changes case is the same service", func(t *testing.T) {
		p := stored()
		p.Service = "HTTP"
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("http", "probed", "", "")); !changed ||
			p.Service != "http" || p.Info != "Apache httpd 2.4.41" {
			t.Errorf("port %+v; want http with the Info kept", p)
		}
	})

	t.Run("info is kept when the service name is kept", func(t *testing.T) {
		p := stored()
		p.ServiceEdited = true
		if _, kept := mergeNmapPort(&p, nmapPortFixture("ssh", "probed", "", "")); !kept ||
			p.Service != "http" || p.Info != "Apache httpd 2.4.41" {
			t.Errorf("kept=%v port %+v; want the typed name and the Info kept", kept, p)
		}
		q := stored()
		if mergeNmapPort(&q, nmapPortFixture("ssh", "table", "", "")); q.Info != "Apache httpd 2.4.41" {
			t.Errorf("a table guess cleared the Info: %+v", q)
		}
	})

	t.Run("a product without its version keeps the details", func(t *testing.T) {
		p := model.Port{Number: 22, Protocol: "tcp", Service: "ssh", Info: "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 Ubuntu Linux; protocol 2.0"}
		if changed, kept := mergeNmapPort(&p, nmapPortFixture("ssh", "probed", "OpenSSH", "")); changed || kept ||
			p.Info != "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 Ubuntu Linux; protocol 2.0" {
			t.Errorf("changed=%v kept=%v info %q; want the version kept", changed, kept, p.Info)
		}
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("ssh", "probed", "OpenSSH", "9.6p1")); !changed || p.Info != "OpenSSH 9.6p1" {
			t.Errorf("info %q; want the newer version", p.Info)
		}
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("ssh", "probed", "OpenSSH", "9")); !changed || p.Info != "OpenSSH 9" {
			t.Errorf("info %q; another exact version replaces it", p.Info)
		}
	})

	// A rescan that tells less about the same service (no version,
	// a version range, "unknown", extra info alone) keeps the stored version.
	t.Run("a less detailed result keeps the stored version", func(t *testing.T) {
		cases := []struct {
			service, info           string // stored
			product, version, extra string // scanned
			wantInfo                string
		}{
			{"mysql", "MySQL 8.0.36-0ubuntu0.22.04.1", "MySQL", "", "unauthorized", "MySQL 8.0.36-0ubuntu0.22.04.1"},
			{"mysql", "MySQL 8.0.36-0ubuntu0.22.04.1", "", "", "unauthorized", "MySQL 8.0.36-0ubuntu0.22.04.1"},
			{"netbios-ssn", "Samba smbd 4.6.2", "Samba smbd", "3.X - 4.X", "workgroup: WORKGROUP", "Samba smbd 4.6.2"},
			{"netbios-ssn", "Samba smbd 4.6.2", "Samba smbd", "4.X", "", "Samba smbd 4.6.2"},
			{"http", "Apache httpd 2.4.41 (Ubuntu)", "Apache httpd", "", "(Ubuntu)", "Apache httpd 2.4.41 (Ubuntu)"},
			{"http", "Apache httpd 2.4.41 (Ubuntu)", "Apache httpd", "unknown", "", "Apache httpd 2.4.41 (Ubuntu)"},
			{"postgresql", "PostgreSQL DB 13.4", "PostgreSQL DB", "9.6.0 or later", "", "PostgreSQL DB 13.4"},
			{"postgresql", "PostgreSQL DB 8.3.7", "PostgreSQL DB", "8.3.0 - 8.3.7", "", "PostgreSQL DB 8.3.7"},
			{"ssh", "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 Ubuntu Linux; protocol 2.0", "OpenSSH", "8.2p1 Ubuntu 4ubuntu0.5", "",
				"OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 Ubuntu Linux; protocol 2.0"},
			// more detail, another exact version or another product replaces it
			{"ssh", "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5", "OpenSSH", "9.6p1 Ubuntu 3ubuntu13", "", "OpenSSH 9.6p1 Ubuntu 3ubuntu13"},
			{"netbios-ssn", "Samba smbd 3.X - 4.X workgroup: WORKGROUP", "Samba smbd", "4.6.2", "", "Samba smbd 4.6.2"},
			{"netbios-ssn", "Samba smbd", "Samba smbd", "", "workgroup: WORKGROUP", "Samba smbd workgroup: WORKGROUP"},
			{"ftp", "vsftpd 3.0.3", "Pure-FTPd", "", "", "Pure-FTPd"},
			{"http", "Jetty 9.4.z-SNAPSHOT", "Jetty", "10.0.18", "", "Jetty 10.0.18"},
		}
		for _, tc := range cases {
			p := model.Port{Number: 80, Protocol: "tcp", Service: tc.service, Info: tc.info}
			np := nmapPortFixture(tc.service, "probed", tc.product, tc.version)
			np.Service.ExtraInfo = tc.extra
			changed, kept := mergeNmapPort(&p, np)
			if p.Info != tc.wantInfo || changed != (tc.wantInfo != tc.info) || kept {
				t.Errorf("%q, scanned %q: info %q (changed=%v kept=%v), want %q",
					tc.info, nmapServiceInfo(np), p.Info, changed, kept, tc.wantInfo)
			}
		}
	})

	// An inconclusive probe never downgrades a known name.
	for _, weak := range []string{"tcpwrapped", "unknown"} {
		t.Run("probed "+weak+" never replaces a name", func(t *testing.T) {
			p := stored()
			if changed, kept := mergeNmapPort(&p, nmapPortFixture(weak, "probed", "", "")); changed || kept || p != stored() {
				t.Errorf("port after a %s probe: %+v", weak, p)
			}
			n := model.Port{Number: 22, Protocol: "tcp"}
			if changed, _ := mergeNmapPort(&n, nmapPortFixture(weak, "probed", "", "")); !changed || n.Service != weak {
				t.Errorf("a new port should still record %q, got %q", weak, n.Service)
			}
		})
	}

	t.Run("info replaced only when non-empty", func(t *testing.T) {
		p := stored()
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("http", "probed", "nginx", "1.18.0")); !changed || p.Info != "nginx 1.18.0" {
			t.Errorf("info = %q, want nginx 1.18.0", p.Info)
		}
	})

	t.Run("scripts merge by id in stable order", func(t *testing.T) {
		p := stored()
		changed, _ := mergeNmapPort(&p, nmapPortFixture("http", "probed", "Apache httpd", "2.4.41",
			nmapScript{ID: "vulners", Output: "CVE-2021-41773 7.5"},
			nmapScript{ID: "http-title", Output: "Dashboard"},
			nmapScript{ID: "http-server-header", Output: ""}, // never blanks a stored output
		))
		want := "http-title=Dashboard | http-server-header=Apache/2.4.41 | vulners=CVE-2021-41773 7.5"
		if got := scriptIDs(t, &p); !changed || got != want {
			t.Errorf("scripts = %q (changed=%v), want %q", got, changed, want)
		}
	})

	// Nmap's "ERROR: Script execution failed" never replaces a result.
	t.Run("failed script run keeps the earlier result", func(t *testing.T) {
		p := stored()
		failed := "ERROR: Script execution failed (use -d to debug)"
		changed, _ := mergeNmapPort(&p, nmapPortFixture("", "", "", "",
			nmapScript{ID: "http-title", Output: failed},
			nmapScript{ID: "ssl-cert", Output: failed}, // a new id: recorded as nmap reported it
		))
		want := "http-title=Login | http-server-header=Apache/2.4.41 | ssl-cert=" + failed
		if got := scriptIDs(t, &p); !changed || got != want {
			t.Errorf("scripts = %q (changed=%v), want %q", got, changed, want)
		}
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("", "", "", "",
			nmapScript{ID: "ssl-cert", Output: "Subject: commonName=app01"})); !changed ||
			!strings.HasSuffix(scriptIDs(t, &p), "ssl-cert=Subject: commonName=app01") {
			t.Errorf("a good result should replace the stored error, got %q", scriptIDs(t, &p))
		}
	})

	t.Run("same scripts again is no change", func(t *testing.T) {
		p := stored()
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("http", "probed", "Apache httpd", "2.4.41",
			nmapScript{ID: "http-title", Output: "Login"})); changed {
			t.Errorf("identical re-import reported a change: %+v", p)
		}
	})

	t.Run("unreadable stored scripts are replaced", func(t *testing.T) {
		p := stored()
		p.ScriptOutput = "not json"
		mergeNmapPort(&p, nmapPortFixture("", "", "", "", nmapScript{ID: "banner", Output: "SSH-2.0"}))
		if got := scriptIDs(t, &p); got != "banner=SSH-2.0" {
			t.Errorf("scripts = %q", got)
		}
		p.ScriptOutput = "not json"
		if changed, _ := mergeNmapPort(&p, nmapPortFixture("", "", "", "")); changed || p.ScriptOutput != "not json" {
			t.Error("a scan without scripts must leave stored script output alone")
		}
	})

	t.Run("values the user typed are kept", func(t *testing.T) {
		p := stored()
		p.ServiceEdited, p.InfoEdited = true, true
		p.Service = "http (admin panel)"
		p.Info = "Apache 2.4.41 - vulnerable to CVE-2021-41773 (confirmed manually)"
		changed, kept := mergeNmapPort(&p, nmapPortFixture("http", "probed", "Apache httpd", "2.4.49",
			nmapScript{ID: "http-vuln-cve2021-41773", Output: "VULNERABLE"}))
		if p.Service != "http (admin panel)" || p.Info != "Apache 2.4.41 - vulnerable to CVE-2021-41773 (confirmed manually)" {
			t.Errorf("import overwrote the user's edit: service %q info %q", p.Service, p.Info)
		}
		if got := scriptIDs(t, &p); !changed || !kept || !strings.HasSuffix(got, "http-vuln-cve2021-41773=VULNERABLE") {
			t.Errorf("scripts should still merge on an edited port (changed=%v kept=%v), got %q", changed, kept, got)
		}
	})

	// A service-name edit does not freeze Info, and the reverse.
	t.Run("an edited service name still gets the scanned version", func(t *testing.T) {
		p := model.Port{Number: 8080, Protocol: "tcp", Service: "jenkins", ServiceEdited: true}
		changed, kept := mergeNmapPort(&p, nmapPortFixture("http", "probed", "Jetty", "10.0.18"))
		if !changed || !kept || p.Service != "jenkins" || p.Info != "Jetty 10.0.18" || !p.ServiceEdited || p.InfoEdited {
			t.Errorf("changed=%v kept=%v port %+v; want jenkins kept and Info Jetty 10.0.18", changed, kept, p)
		}
	})

	// Renaming the service keeps the scanned version up to date.
	t.Run("an edited service name doesn't freeze a scanned version", func(t *testing.T) {
		p := model.Port{Number: 22, Protocol: "tcp", Service: "ssh (key auth only)", Info: "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5", ServiceEdited: true}
		changed, kept := mergeNmapPort(&p, nmapPortFixture("ssh", "probed", "OpenSSH", "9.6p1 Ubuntu 3ubuntu13"))
		if !changed || !kept || p.Service != "ssh (key auth only)" || p.Info != "OpenSSH 9.6p1 Ubuntu 3ubuntu13" {
			t.Errorf("changed=%v kept=%v port %+v; want the name kept and the new version", changed, kept, p)
		}
	})

	t.Run("edited info is kept while the service name updates", func(t *testing.T) {
		p := stored()
		p.Info, p.InfoEdited = "Apache 2.4.41 - CVE-2021-41773 confirmed", true
		changed, kept := mergeNmapPort(&p, nmapPortFixture("https", "probed", "Apache httpd", "2.4.57"))
		if !changed || !kept || p.Service != "https" || p.Info != "Apache 2.4.41 - CVE-2021-41773 confirmed" {
			t.Errorf("changed=%v kept=%v port %+v", changed, kept, p)
		}
	})

	t.Run("an empty field is filled even if marked", func(t *testing.T) {
		p := model.Port{Number: 22, Protocol: "tcp", Service: "ssh", ServiceEdited: true, InfoEdited: true}
		changed, kept := mergeNmapPort(&p, nmapPortFixture("ssh", "probed", "OpenSSH", "9.6p1"))
		if !changed || kept || p.Info != "OpenSSH 9.6p1" || p.InfoEdited || !p.ServiceEdited {
			t.Errorf("changed=%v kept=%v port %+v; want Info filled and no longer marked", changed, kept, p)
		}
	})

	t.Run("nothing to keep when the scan agrees", func(t *testing.T) {
		p := stored()
		p.ServiceEdited, p.InfoEdited = true, true
		if changed, kept := mergeNmapPort(&p, nmapPortFixture("http", "probed", "Apache httpd", "2.4.41")); changed || kept {
			t.Errorf("changed=%v kept=%v; want neither", changed, kept)
		}
		if _, kept := mergeNmapPort(&p, nmapPortFixture("http-alt", "table", "", "")); kept {
			t.Error("a table guess would not have replaced the name, so it was not kept over anything")
		}
	})
}

func TestPortChanges(t *testing.T) {
	before := model.Port{Service: "ssh", Info: "", ScriptOutput: "[]", InfoEdited: true}
	after := before
	after.Info, after.InfoEdited = "OpenSSH 9.6p1", false
	if got := fmt.Sprint(portChanges(before, after)); got != "map[info:OpenSSH 9.6p1 info_edited:false]" {
		t.Errorf("portChanges = %s", got)
	}
	if got := portChanges(before, before); len(got) != 0 {
		t.Errorf("no change should write nothing, got %v", got)
	}
}

func TestPortEditChanges(t *testing.T) {
	u16 := func(n uint16) *uint16 { return &n }
	str := func(s string) *string { return &s }
	yes, no := func() *bool { b := true; return &b }(), func() *bool { b := false; return &b }()
	stored := model.Port{Number: 80, Protocol: "tcp", Service: "http", Info: "Apache httpd 2.4.41 (Ubuntu)"}
	edited := stored
	edited.ServiceEdited, edited.InfoEdited = true, true
	ipPort := model.Port{Number: 0, Protocol: "ip", Service: "hopopt"}

	cases := []struct {
		name string
		p    model.Port
		edit portEdit
		want string // fmt.Sprint of the columns, or "error: <message>"
	}{
		{"modal saves unchanged", stored,
			portEdit{Number: u16(80), Protocol: str("tcp"), Service: str("http"), Info: str("Apache httpd 2.4.41 (Ubuntu)")},
			"map[info:Apache httpd 2.4.41 (Ubuntu) info_edited:false number:80 protocol:tcp service:http service_edited:false]"},
		{"whitespace only", stored, portEdit{Service: str(" http "), Info: str("Apache httpd 2.4.41 (Ubuntu) ")},
			"map[info:Apache httpd 2.4.41 (Ubuntu)  info_edited:false service: http  service_edited:false]"},
		{"info edited marks only info", stored, portEdit{Service: str("http"), Info: str("Apache 2.4.41 - CVE-2021-41773 confirmed")},
			"map[info:Apache 2.4.41 - CVE-2021-41773 confirmed info_edited:true service:http service_edited:false]"},
		{"service edited marks only service", stored, portEdit{Service: str("http-admin"), Info: str("Apache httpd 2.4.41 (Ubuntu)")},
			"map[info:Apache httpd 2.4.41 (Ubuntu) info_edited:false service:http-admin service_edited:true]"},
		{"cleared info is not marked (scans fill it again)", edited, portEdit{Info: str("")},
			"map[info: info_edited:false]"},
		{"marked values saved unchanged stay marked", edited, portEdit{Service: str("http"), Info: str("Apache httpd 2.4.41 (Ubuntu)")},
			"map[info:Apache httpd 2.4.41 (Ubuntu) info_edited:true service:http service_edited:true]"},
		{"number and protocol only leave service and info alone", stored, portEdit{Number: u16(8080), Protocol: str("tcp")},
			"map[number:8080 protocol:tcp]"},
		{"info only", stored, portEdit{Info: str("manual note")}, "map[info:manual note info_edited:true]"},
		{"clear a mark", edited, portEdit{InfoEdited: no}, "map[info_edited:false]"},
		{"set a mark", stored, portEdit{ServiceEdited: yes}, "map[service_edited:true]"},
		{"a mark needs a value", model.Port{Number: 22, Protocol: "tcp"}, portEdit{InfoEdited: yes}, "map[info_edited:false]"},
		{"an explicit mark wins over the change", stored, portEdit{Service: str("jenkins"), ServiceEdited: no},
			"map[service:jenkins service_edited:false]"},
		{"ip protocol 0", ipPort, portEdit{Number: u16(0), Protocol: str("ip"), Info: str("IPv6 hop-by-hop")},
			"map[info:IPv6 hop-by-hop info_edited:true number:0 protocol:ip]"},
		{"ip protocol 256", ipPort, portEdit{Number: u16(256), Protocol: str("ip")}, "error: " + errPortNumber.Error()},
		{"tcp port 0", stored, portEdit{Number: u16(0), Protocol: str("tcp")}, "error: " + errPortNumber.Error()},
		{"a new protocol is checked against the stored number", ipPort, portEdit{Protocol: str("tcp")}, "error: " + errPortNumber.Error()},
		{"a new number is checked against the stored protocol", ipPort, portEdit{Number: u16(300)}, "error: " + errPortNumber.Error()},
		{"unknown protocol", stored, portEdit{Number: u16(80), Protocol: str("icmp")}, "error: protocol must be tcp, udp, sctp, or ip"},
		{"protocol case is not normalised", stored, portEdit{Protocol: str("TCP")}, "error: protocol must be tcp, udp, sctp, or ip"},
		{"empty edit", stored, portEdit{}, "error: nothing to update"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cols, err := tc.edit.changes(tc.p)
			got := fmt.Sprint(cols)
			if err != nil {
				got = "error: " + err.Error()
			}
			if got != tc.want {
				t.Errorf("changes = %s\n            want %s", got, tc.want)
			}
		})
	}
}

// The edit modal's body and API clients' partial bodies bind as expected.
func TestPortEditBinding(t *testing.T) {
	var full, partial, nulls portEdit
	if err := json.Unmarshal([]byte(`{"number":22,"protocol":"tcp","service":"ssh","info":""}`), &full); err != nil ||
		full.Number == nil || *full.Number != 22 || full.Info == nil || *full.Info != "" || full.ServiceEdited != nil {
		t.Errorf("modal body bound as %+v (err %v)", full, err)
	}
	if err := json.Unmarshal([]byte(`{"info_edited":false}`), &partial); err != nil ||
		partial.InfoEdited == nil || *partial.InfoEdited || partial.Number != nil || partial.Service != nil {
		t.Errorf("partial body bound as %+v (err %v)", partial, err)
	}
	if err := json.Unmarshal([]byte(`{"service":null,"info":null}`), &nulls); err != nil || nulls != (portEdit{}) {
		t.Errorf("null fields should count as omitted: %+v (err %v)", nulls, err)
	}
}

func TestNewManualPort(t *testing.T) {
	bind := func(body string) (addPortReq, error) {
		var req addPortReq
		err := binding.JSON.BindBody([]byte(body), &req)
		return req, err
	}
	cases := []struct {
		body, want string // want: "<number>/<protocol> service_edited info_edited", or "error"
	}{
		{`{"number":8080,"protocol":"tcp","service":"jenkins (admin:admin works)"}`, "8080/tcp true false"},
		{`{"number":9090,"protocol":"tcp","info":"cockpit - default creds"}`, "9090/tcp false true"},
		{`{"number":3000,"protocol":"tcp","service":"  "}`, "3000/tcp false false"},
		{`{"number":0,"protocol":"ip","service":"hopopt"}`, "0/ip true false"},
		{`{"number":255,"protocol":"ip"}`, "255/ip false false"},
		{`{"number":256,"protocol":"ip"}`, "error"},
		{`{"number":0,"protocol":"tcp"}`, "error"},
		{`{"protocol":"tcp"}`, "error"},
		{`{"number":8,"protocol":"icmp"}`, "error"},
		{`{"number":70000,"protocol":"tcp"}`, "error"},
	}
	for _, tc := range cases {
		req, err := bind(tc.body)
		var p model.Port
		if err == nil {
			p, err = newManualPort(uuid.New(), req)
		}
		got := "error"
		if err == nil {
			got = fmt.Sprintf("%d/%s %v %v", p.Number, p.Protocol, p.ServiceEdited, p.InfoEdited)
		}
		if got != tc.want {
			t.Errorf("AddPort %s: got %s (err %v), want %s", tc.body, got, err, tc.want)
		}
	}
}

func TestFindNmapHost(t *testing.T) {
	hosts := []model.Host{
		{Identifier: "2001:DB8::10"}, {Identifier: "dc01.lab"}, {Identifier: "WEB01.LAB"},
		{Identifier: "192.168.1.11"}, {Identifier: "00:0C:29:AA:BB:CC"},
	}
	run := mustParseNmap(t, `<nmaprun>
<host><address addr="2001:db8::10" addrtype="ipv6"/></host>
<host><address addr="192.168.1.11" addrtype="ipv4"/><hostnames><hostname name="dc01.lab"/></hostnames></host>
<host><address addr="192.168.1.10" addrtype="ipv4"/><hostnames><hostname name="web01.lab"/></hostnames></host>
<host><address addr="10.9.9.9" addrtype="ipv4"/></host>
<host><address addr="00:0C:29:AA:BB:CC" addrtype="mac"/></host>
</nmaprun>`)
	want := []string{
		"2001:DB8::10", // the same IPv6 address written differently
		"192.168.1.11", // an address match wins over the hostname match on dc01.lab
		"WEB01.LAB",    // hostname, case-insensitive
		"",             // new host
		"00:0C:29:AA:BB:CC",
	}
	shared := nmapSharedNames(run.Hosts)
	for i, nh := range run.Hosts {
		got, found := findNmapHost(hosts, nh, nh.bulkIdentifier(), shared)
		if got.Identifier != want[i] || found != (want[i] != "") {
			t.Errorf("%s matched %q (found %v), want %q", nh.name(), got.Identifier, found, want[i])
		}
	}
}

// Bulk import never merges two addresses into one existing host
// through a hostname they share, and a host named by an IP address only
// matches that address.
func TestFindNmapHostSharedName(t *testing.T) {
	hosts := []model.Host{{Identifier: "portal.lab"}, {Identifier: "app.lab"}, {Identifier: "10.0.0.5"}}
	run := mustParseNmap(t, `<nmaprun>
<host><status state="up"/><address addr="10.50.0.11" addrtype="ipv4"/><hostnames><hostname name="portal.lab" type="PTR"/></hostnames></host>
<host><status state="up"/><address addr="10.50.0.12" addrtype="ipv4"/><hostnames><hostname name="Portal.Lab" type="PTR"/></hostnames></host>
<host><status state="up"/><address addr="10.60.0.1" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="PTR"/></hostnames></host>
<host><status state="up"/><address addr="10.60.0.1" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="PTR"/></hostnames></host>
<host><status state="down"/><address addr="10.60.0.2" addrtype="ipv4"/><hostnames><hostname name="app.lab" type="PTR"/></hostnames></host>
<host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/><hostnames><hostname name="10.0.0.5" type="user"/></hostnames></host>
</nmaprun>`)
	shared := nmapSharedNames(run.Hosts)
	if fmt.Sprint(shared) != "map[portal.lab:true]" {
		t.Errorf("shared names = %v, want only portal.lab (app.lab is one address up)", shared)
	}
	want := []string{"", "", "app.lab", "app.lab", "(down, not imported)", ""}
	for i, nh := range run.Hosts {
		if !nh.up() {
			continue
		}
		got, found := findNmapHost(hosts, nh, nh.bulkIdentifier(), shared)
		if got.Identifier != want[i] || found != (want[i] != "") {
			t.Errorf("entry %d (%s) matched %q (found %v), want %q", i, nh.name(), got.Identifier, found, want[i])
		}
	}
}

// In a bulk import of a -Pn scan, an address with no open port
// neither makes a hostname shared nor matches a host by that name, so the
// address with open ports still updates the host named after it. It still
// matches a host whose identifier is its address.
func TestFindNmapHostPn(t *testing.T) {
	hosts := []model.Host{{Identifier: "files01.corp.local"}, {Identifier: "app.lab"}, {Identifier: "10.40.0.2"}}
	for _, tc := range []struct {
		xml  string
		want []string // per entry: the identifier of the matched host, "" for none
	}{
		{nmapPnStalePTRXML, []string{"", "files01.corp.local", "", ""}},
		{nmapPnResolveAllXML, []string{"app.lab", "10.40.0.2"}},
	} {
		run := mustParseNmap(t, tc.xml)
		shared := nmapSharedNames(run.Hosts)
		if len(shared) != 0 {
			t.Errorf("shared names = %v, want none (one address has open ports)", shared)
		}
		for i, nh := range run.Hosts {
			got, found := findNmapHost(hosts, nh, nh.bulkIdentifier(), shared)
			if got.Identifier != tc.want[i] || found != (tc.want[i] != "") {
				t.Errorf("%s matched %q (found %v), want %q", nh.name(), got.Identifier, found, tc.want[i])
			}
		}
	}
}

// In a bulk import of a -Pn scan, the address a target name
// resolved to still claims that name without an open port, so another
// machine that only has the name as a PTR record gets a host of its own
// instead of updating the host named after the target.
func TestFindNmapHostPnTarget(t *testing.T) {
	hosts := []model.Host{{Identifier: "app.lab"}, {Identifier: "10.40.0.1"}}
	run := mustParseNmap(t, nmapPnTargetStalePTRXML)
	shared := nmapSharedNames(run.Hosts)
	if fmt.Sprint(shared) != "map[app.lab:true]" {
		t.Errorf("shared names = %v, want app.lab (the target's address and a PTR-only address)", shared)
	}
	want := []string{"10.40.0.1", ""} // its own address; a new host, not app.lab
	for i, nh := range run.Hosts {
		got, found := findNmapHost(hosts, nh, nh.bulkIdentifier(), shared)
		if got.Identifier != want[i] || found != (want[i] != "") {
			t.Errorf("%s matched %q (found %v), want %q", nh.name(), got.Identifier, found, want[i])
		}
	}
}

// Only up entries count as seen, and -Pn (reason "user-set") reports every
// target up, so those also need an open port that can be imported.
func TestNmapHostSeen(t *testing.T) {
	run := mustParseNmap(t, `<nmaprun>
<host><status state="up" reason="user-set"/><address addr="10.10.0.1"/><ports><extraports state="filtered" count="1000"/></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.10.0.2"/><ports><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.10.0.3"/><ports><port protocol="tcp" portid="70000"><state state="open"/></port></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.10.0.4"/><ports><port protocol="tcp" portid="445"><state state="open"/></port></ports></host>
<host><status state="up" reason="echo-reply"/><address addr="10.10.0.5"/></host>
<host><address addr="10.10.0.6"/></host>
<host><status state="down" reason="no-response"/><address addr="10.10.0.7"/></host>
</nmaprun>`)
	var seen []string
	for _, nh := range run.Hosts {
		if nh.seen() {
			seen = append(seen, nh.name())
		}
	}
	if got, want := strings.Join(seen, " "), "10.10.0.4 10.10.0.5 10.10.0.6"; got != want {
		t.Errorf("seen entries %q, want %q", got, want)
	}
}

// Bulk import: -Pn reports every target up with reason "user-set"; only
// those with an open port to import may become new hosts.
func TestNmapBulkEntries(t *testing.T) {
	run := mustParseNmap(t, `<nmaprun>
<host><status state="up" reason="user-set"/><address addr="10.10.0.1" addrtype="ipv4"/><ports><extraports state="filtered" count="1000"/></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.10.0.3" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open"/></port><port protocol="tcp" portid="139"><state state="filtered"/></port></ports></host>
<host><status state="up" reason="user-set"/><address addr="10.10.0.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="70000"><state state="open"/></port></ports></host>
<host><status state="up" reason="arp-response"/><address addr="10.60.0.1" addrtype="ipv4"/><address addr="00:0C:29:00:00:01" addrtype="mac"/></host>
<host><address addr="fe80::1" addrtype="ipv6"/><address addr="10.70.0.1" addrtype="ipv4"/></host>
</nmaprun>`)
	var got []string
	for _, nh := range run.Hosts {
		valid, invalid := nh.openPorts()
		got = append(got, fmt.Sprintf("%s %s %d/%d", nh.bulkIdentifier(), nh.Status.Reason, valid, invalid))
	}
	want := "10.10.0.1 user-set 0/0 | 10.10.0.3 user-set 1/0 | 10.10.0.4 user-set 0/1 | 10.60.0.1 arp-response 0/0 | 10.70.0.1  0/0"
	if strings.Join(got, " | ") != want {
		t.Errorf("entries:\n got %s\nwant %s", strings.Join(got, " | "), want)
	}
}

// Bundles round-trip the per-field flags; older bundles import unmarked.
func TestExportPortEditFlags(t *testing.T) {
	b, err := json.Marshal(exportPort{Number: 22, Protocol: "tcp", Service: "ssh"})
	if err != nil || strings.Contains(string(b), "_edited") {
		t.Errorf("unmarked port exported as %s (err %v); want no *_edited keys", b, err)
	}
	b, _ = json.Marshal(exportPort{Number: 80, Protocol: "tcp", Service: "jenkins", Info: "Jetty", ServiceEdited: true})
	var back exportPort
	if err := json.Unmarshal(b, &back); err != nil || !strings.Contains(string(b), `"service_edited":true`) {
		t.Fatalf("marked port exported as %s (err %v)", b, err)
	}
	if s, i := back.editFlags(); !s || i {
		t.Errorf("round trip of %s: flags %v %v, want service only", b, s, i)
	}

	cases := []struct{ bundle, want string }{
		{`{"number":80,"protocol":"tcp","service":"http","created_at":"2025-01-01T00:00:00Z"}`, "false false"},
		{`{"number":80,"protocol":"tcp","service":"http","info":"note","service_edited":true,"info_edited":true}`, "true true"},
		{`{"number":80,"protocol":"tcp","info_edited":true}`, "false false"},
	}
	for _, tc := range cases {
		var ep exportPort
		if err := json.Unmarshal([]byte(tc.bundle), &ep); err != nil {
			t.Fatalf("%s: %v", tc.bundle, err)
		}
		if s, i := ep.editFlags(); fmt.Sprint(s, i) != tc.want {
			t.Errorf("%s imports with flags %v %v, want %s", tc.bundle, s, i, tc.want)
		}
	}
}
