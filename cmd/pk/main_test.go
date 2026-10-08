package main

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestExitStatus(t *testing.T) {
	cases := []struct {
		script string
		want   int
	}{
		{"exit 0", 0},
		{"exit 4", 4},
		{"nonexistent-command-for-pk-test", 127},
		{"kill -TERM $$", 128 + 15},
	}
	for _, tc := range cases {
		if got := exitStatus(exec.Command("sh", "-c", tc.script).Run()); got != tc.want {
			t.Errorf("exitStatus(%q) = %d, want %d", tc.script, got, tc.want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"10.0.0.5":                  "10.0.0.5",
		"":                          "''",
		"nmap -sV 10.0.0.5":         "'nmap -sV 10.0.0.5'",
		"it's":                      `'it'\''s'`,
		"https://example.com/a?b=1": "'https://example.com/a?b=1'",
		"/home/u/f-1_2.txt":         "/home/u/f-1_2.txt",
		"$(rm -rf ~)":               "'$(rm -rf ~)'",
		"line1\nline2":              "'line1\nline2'",
		"Cam 1000 (rev2)":           "'Cam 1000 (rev2)'",
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestUnsentPattern(t *testing.T) {
	now := time.Date(2026, 10, 8, 9, 30, 5, 0, time.UTC)
	cases := []struct{ target, tool, want string }{
		{"10.0.0.5", "nmap", "20261008-093005-10.0.0.5-nmap-*.txt"},
		{"https://example.com/a b", "curl", "20261008-093005-https_example.com_a_b-curl-*.txt"},
		{"../../etc/passwd", "../x", "20261008-093005-etc_passwd-x-*.txt"},
		{strings.Repeat("a", 100), "t", "20261008-093005-" + strings.Repeat("a", 64) + "-t-*.txt"},
	}
	for _, tc := range cases {
		if got := unsentPattern(now, tc.target, tc.tool); got != tc.want {
			t.Errorf("unsentPattern(%q, %q) = %q, want %q", tc.target, tc.tool, got, tc.want)
		}
	}
}

func TestResendCommand(t *testing.T) {
	got := resendCommand("10.0.0.5", "Client A", "nmap", "nmap -sV 10.0.0.5", "/s/u/f.txt")
	want := "pk --target 10.0.0.5 --assessment 'Client A' --tool nmap --command 'nmap -sV 10.0.0.5' < /s/u/f.txt"
	if got != want {
		t.Errorf("resendCommand = %s, want %s", got, want)
	}
	if got := resendCommand("h", "", "unknown", "", "/f"); got != "pk --target h --tool unknown < /f" {
		t.Errorf("resendCommand without assessment/command = %s", got)
	}
}

func TestSameID(t *testing.T) {
	const id = "a0cb7510-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
	for _, s := range []string{id, strings.ToUpper(id), "{" + id + "}", "urn:uuid:" + id, strings.ReplaceAll(id, "-", "")} {
		if !sameID(s, id) {
			t.Errorf("sameID(%q, id) = false, want true", s)
		}
	}
	if sameID(id, "") || sameID("Client A", id) || sameID(id, "b0cb7510-1c2d-4e5f-8a9b-0c1d2e3f4a5b") {
		t.Error("sameID matched a different or missing id")
	}
}
