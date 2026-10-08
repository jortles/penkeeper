package main

import (
	"fmt"
	"strings"
)

// envExamplePlaceholder is the JWT_SECRET value older .env.example files
// shipped with; it is public, so it must never sign sessions.
const envExamplePlaceholder = "change-me-to-a-random-secret"

const minSecretLen = 32

// insecureSecretReason returns why v must not be used as JWT_SECRET or
// ENCRYPTION_KEY, or "" if it is acceptable.
func insecureSecretReason(v string) string {
	switch {
	case v == envExamplePlaceholder:
		return "it is the public placeholder from .env.example"
	case strings.Contains(v, "$(") || strings.Contains(v, "${") || strings.Contains(v, "`"):
		return "it contains unexpanded shell syntax such as $(...); .env files are not run " +
			"through a shell, so paste the generated value itself"
	case len(v) < minSecretLen:
		return fmt.Sprintf("it is only %d bytes; use at least %d random bytes", len(v), minSecretLen)
	}
	return ""
}

// insecureAllowed reports whether PK_ALLOW_INSECURE_SECRETS (a comma-separated
// list of secret names, or 1/true/all for every secret) lets the named secret
// through.
func insecureAllowed(setting, name string) bool {
	for _, f := range strings.Split(setting, ",") {
		f = strings.TrimSpace(f)
		if f == "1" || strings.EqualFold(f, "true") || strings.EqualFold(f, "all") || f == name {
			return true
		}
	}
	return false
}

// checkSecrets validates JWT_SECRET and ENCRYPTION_KEY (encKey may be empty:
// the at-rest key is then derived from JWT_SECRET). It returns the message to
// print before refusing to start, or "" together with a warning for every
// insecure secret that PK_ALLOW_INSECURE_SECRETS lets through.
func checkSecrets(jwtSecret, encKey, allow string) (refusal string, warnings []string) {
	jwtWhy := insecureSecretReason(jwtSecret)
	encWhy := ""
	if encKey != "" {
		encWhy = insecureSecretReason(encKey)
	}

	var b strings.Builder
	if jwtWhy != "" {
		if insecureAllowed(allow, "JWT_SECRET") {
			warnings = append(warnings, "JWT_SECRET is insecure ("+jwtWhy+"). Anyone who knows "+
				"or guesses it can forge sessions for any user. Use this only for local development.")
		} else {
			fmt.Fprintf(&b, "  JWT_SECRET is insecure: %s.\n\n", jwtWhy)
			if encKey == "" {
				b.WriteString(`  ENCRYPTION_KEY is unset, so stored credentials and 2FA secrets are
  encrypted with a key derived from JWT_SECRET. To change JWT_SECRET on an
  existing install without losing them, edit .env:
    1. Add ENCRYPTION_KEY=<the current JWT_SECRET value, exactly as it is>.
       The key is SHA-256 of the value, so this yields the same key as today.
    2. Add PK_ALLOW_INSECURE_SECRETS=ENCRYPTION_KEY, because that value is as
       weak as the old JWT_SECRET. Data saved under it stays only as protected
       as it was; re-entering it under a new key is the only way to fix that.
    3. Set JWT_SECRET to the output of: openssl rand -hex 32
       Every user and the pk CLI then has to log in again.
  On a new install with no saved data, just set JWT_SECRET (and ENCRYPTION_KEY)
  to two different outputs of: openssl rand -hex 32

`)
			} else {
				b.WriteString(`  Set JWT_SECRET to the output of: openssl rand -hex 32
  ENCRYPTION_KEY is set separately, so stored data is not affected; every user
  and the pk CLI just has to log in again.

`)
			}
		}
	}
	if encWhy != "" {
		if insecureAllowed(allow, "ENCRYPTION_KEY") {
			warnings = append(warnings, "ENCRYPTION_KEY is insecure ("+encWhy+"). Anyone with a "+
				"copy of the database can decrypt stored credentials and 2FA secrets; only "+
				"re-entering them under a new key fixes that.")
		} else {
			fmt.Fprintf(&b, "  ENCRYPTION_KEY is insecure: %s.\n\n", encWhy)
			b.WriteString(`  Changing ENCRYPTION_KEY makes credentials and 2FA secrets saved under it
  unreadable. On a new install, set it to the output of: openssl rand -hex 32
  If data is already saved under it, keep it and add
  PK_ALLOW_INSECURE_SECRETS=ENCRYPTION_KEY to .env.

`)
		}
	}
	if b.Len() == 0 {
		return "", warnings
	}
	return `
================================================================================
  REFUSING TO START: INSECURE SECRET
================================================================================

` + b.String() + `  .env takes one KEY=value per line and is not run through a shell: paste
  the generated value, not "$(openssl rand -hex 32)".

  For local development only, PK_ALLOW_INSECURE_SECRETS=1 starts the server
  anyway with a warning.

================================================================================`, warnings
}
