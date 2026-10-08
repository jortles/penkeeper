package penkeeper

import "embed"

// FrontendFS holds the compiled frontend (HTML, JS, CSS) embedded at build time.
// This allows the server binary to run without a separate frontend/ directory.
//
//go:embed frontend
var FrontendFS embed.FS
