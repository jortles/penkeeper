package main

import (
	"strings"
	"testing"
)

func TestInsecureSecretReason(t *testing.T) {
	good := "0123456789abcdef0123456789abcdef"
	cases := map[string]bool{
		good:                            false,
		envExamplePlaceholder:           true,
		"$(openssl rand -hex 32)":       true,
		"${JWT}" + good:                 true,
		"`openssl rand -hex 32`" + good: true,
		good[:31]:                       true,
		"":                              true,
	}
	for v, bad := range cases {
		if got := insecureSecretReason(v) != ""; got != bad {
			t.Errorf("insecureSecretReason(%q) insecure=%v, want %v", v, got, bad)
		}
	}
}

func TestInsecureAllowed(t *testing.T) {
	cases := []struct {
		setting, name string
		want          bool
	}{
		{"", "JWT_SECRET", false},
		{"0", "JWT_SECRET", false},
		{"1", "JWT_SECRET", true},
		{"true", "ENCRYPTION_KEY", true},
		{"all", "JWT_SECRET", true},
		{"ENCRYPTION_KEY", "ENCRYPTION_KEY", true},
		{"ENCRYPTION_KEY", "JWT_SECRET", false},
		{" JWT_SECRET , ENCRYPTION_KEY", "JWT_SECRET", true},
	}
	for _, c := range cases {
		if got := insecureAllowed(c.setting, c.name); got != c.want {
			t.Errorf("insecureAllowed(%q, %q) = %v, want %v", c.setting, c.name, got, c.want)
		}
	}
}

func TestCheckSecrets(t *testing.T) {
	strong := strings.Repeat("ab", 32)
	strong2 := strings.Repeat("cd", 32)

	if r, w := checkSecrets(strong, "", ""); r != "" || len(w) != 0 {
		t.Fatalf("strong JWT_SECRET refused: %q %v", r, w)
	}
	if r, w := checkSecrets(strong, strong2, ""); r != "" || len(w) != 0 {
		t.Fatalf("strong secrets refused: %q %v", r, w)
	}

	// Placeholder with no ENCRYPTION_KEY: refuse, and explain how to keep the
	// derived at-rest key while rotating JWT_SECRET.
	r, _ := checkSecrets(envExamplePlaceholder, "", "")
	for _, want := range []string{"JWT_SECRET is insecure", "ENCRYPTION_KEY=<the current JWT_SECRET value", "PK_ALLOW_INSECURE_SECRETS=ENCRYPTION_KEY"} {
		if !strings.Contains(r, want) {
			t.Errorf("refusal lacks %q:\n%s", want, r)
		}
	}

	// That advice must actually start: old value pinned as ENCRYPTION_KEY,
	// new JWT_SECRET, ENCRYPTION_KEY allowed explicitly.
	if r, w := checkSecrets(strong, envExamplePlaceholder, "ENCRYPTION_KEY"); r != "" || len(w) != 1 {
		t.Fatalf("documented rotation path refused: %q %v", r, w)
	}
	// ...but the narrow allowance does not admit a weak JWT_SECRET.
	if r, _ := checkSecrets(envExamplePlaceholder, strong, "ENCRYPTION_KEY"); r == "" {
		t.Fatal("weak JWT_SECRET accepted with PK_ALLOW_INSECURE_SECRETS=ENCRYPTION_KEY")
	}

	// Unexpanded shell syntax in ENCRYPTION_KEY is refused too.
	if r, _ := checkSecrets(strong, "$(openssl rand -hex 32)", ""); !strings.Contains(r, "ENCRYPTION_KEY is insecure") {
		t.Fatalf("shell-syntax ENCRYPTION_KEY not refused: %q", r)
	}

	// Development escape hatch: start with warnings for both.
	if r, w := checkSecrets("short", "short", "1"); r != "" || len(w) != 2 {
		t.Fatalf("PK_ALLOW_INSECURE_SECRETS=1: refusal %q, %d warnings", r, len(w))
	}
}
