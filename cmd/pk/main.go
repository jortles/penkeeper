// pk – Penkeeper CLI pipe tool
//
// Usage:
//
//	pk login                              # authenticate and save token
//	<tool> | pk --target <ip/hostname>   # pipe tool output to a host
//
// Flags (pipe mode):
//
//	--target     <ip>   Host identifier to attach output to (required)
//	--assessment <name> Assessment (name or id) the target is in (optional)
//	--tool       <name> Tool name tag (default: first word of --command, else "unknown")
//	--command    <cmd>  Full command string for record-keeping (optional)
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type config struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

func configPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "penkeeper", "config.json")
}

func loadConfig() (config, error) {
	var cfg config
	data, err := os.ReadFile(configPath())
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

func saveConfig(cfg config) error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, data, 0600)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

// httpClient bounds every request, so a server that accepts the connection
// but never answers can't block pk forever: 30 s to connect and 10 s for the
// TLS handshake (the default transport's), and a minute for the answer once
// the request is sent. There is no overall limit, so a large upload on a slow
// link still gets through.
var httpClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = time.Minute
	return &http.Client{Transport: t}
}()

func apiPost(url, token string, body any) (*http.Response, error) {
	// Tool output is full of <, > and &: escaping each to <-style text
	// would multiply its size by six and hit the server's body cap early.
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, &b)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return httpClient.Do(req)
}

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

// ---------------------------------------------------------------------------
// Prompt helpers
// ---------------------------------------------------------------------------

func prompt(label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("%s: ", label)
	}
	var val string
	fmt.Fscanln(os.Stdin, &val)
	val = strings.TrimSpace(val)
	if val == "" {
		return defaultVal
	}
	return val
}

func promptPassword(label string) string {
	fmt.Printf("%s: ", label)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		// Fallback for non-TTY
		var s string
		fmt.Fscanln(os.Stdin, &s)
		return strings.TrimSpace(s)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Login subcommand
// ---------------------------------------------------------------------------

// warnIfInsecureURL prints a warning when the server URL uses plain http to a
// non-loopback host, since the saved bearer token is then sent in cleartext.
func warnIfInsecureURL(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	if u.Scheme != "http" {
		return
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return
	}
	fmt.Fprintf(os.Stderr, "[!] Warning: %q uses plain HTTP to a remote host. Your login token "+
		"will be sent in cleartext. Use https:// (e.g. behind a reverse proxy) for remote servers.\n", rawURL)
}

func cmdLogin() error {
	existing, _ := loadConfig()
	defaultURL := existing.URL
	if defaultURL == "" {
		defaultURL = "http://localhost:1338"
	}

	apiURL := prompt("API URL", defaultURL)
	apiURL = strings.TrimRight(apiURL, "/")
	warnIfInsecureURL(apiURL)
	email := prompt("Email", "")
	password := promptPassword("Password")

	// Step 1: password login
	resp, err := apiPost(apiURL+"/api/auth/login", "", map[string]string{
		"email":    email,
		"password": password,
	})
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	var loginResp map[string]any
	if err := decodeJSON(resp.Body, &loginResp); err != nil {
		return fmt.Errorf("unexpected response from server")
	}

	if resp.StatusCode != http.StatusOK {
		msg, _ := loginResp["error"].(string)
		return fmt.Errorf("login failed: %s", msg)
	}

	token := ""

	// Step 2: TOTP if required
	if requiresTOTP, _ := loginResp["requires_totp"].(bool); requiresTOTP {
		partialToken, _ := loginResp["partial_token"].(string)
		code := prompt("2FA code", "")

		resp2, err := apiPost(apiURL+"/api/auth/totp", "", map[string]string{
			"partial_token": partialToken,
			"code":          code,
		})
		if err != nil {
			return fmt.Errorf("TOTP request failed: %w", err)
		}
		defer resp2.Body.Close()

		var totpResp map[string]any
		if err := decodeJSON(resp2.Body, &totpResp); err != nil {
			return errors.New("unexpected TOTP response")
		}
		if resp2.StatusCode != http.StatusOK {
			msg, _ := totpResp["error"].(string)
			return fmt.Errorf("TOTP failed: %s", msg)
		}
		token, _ = totpResp["token"].(string)
	} else {
		token, _ = loginResp["token"].(string)
	}

	if token == "" {
		return errors.New("server did not return a token")
	}

	cfg := config{URL: apiURL, Token: token}
	if err := saveConfig(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("[+] Logged in. Token saved to %s\n", configPath())
	return nil
}

// ---------------------------------------------------------------------------
// Pipe subcommand (default)
// ---------------------------------------------------------------------------

// runCapture executes shellCmd inside a PTY so the subprocess sees a real
// TTY on all file descriptors. This means isatty() returns true, and tools
// like smbclient display interactive prompts (e.g. password prompts) as
// normal. All output is shown on the terminal in real-time and also
// captured for upload. Falls back to a simple pipe if stdin is not a TTY
// (e.g. when pk itself is run non-interactively); stdout and stderr are then
// shown on pk's stdout and stderr and both captured. It returns the command's
// exit status; err is set only when the command could not be run.
func runCapture(shellCmd string) (output string, status int, err error) {
	cmd := exec.Command("sh", "-c", shellCmd)

	// A reader that goes away early (| head, quitting less) must not kill pk
	// with SIGPIPE and lose the capture: with a handler, the write just
	// fails. Unlike signal.Ignore, the command still gets the default action.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Non-interactive fallback: each stream is shown where it would go
		// without pk, and both are captured in the order they arrive.
		var buf lockedBuf
		cmd.Stdin = os.Stdin
		cmd.Stdout = io.MultiWriter(&bestEffort{w: os.Stdout}, &buf)
		cmd.Stderr = io.MultiWriter(&bestEffort{w: os.Stderr}, &buf)
		// A child left running in the background (ssh -f, nohup x &) keeps the
		// pipes open; stop waiting for it shortly after sh itself exits.
		cmd.WaitDelay = 2 * time.Second
		if err := cmd.Start(); err != nil {
			return "", 0, err
		}
		err := cmd.Wait()
		if errors.Is(err, exec.ErrWaitDelay) {
			err = nil // sh exited 0; only a background child still held the pipes
		}
		return buf.b.String(), exitStatus(err), nil
	}

	// Start the command under a PTY so the subprocess sees a real terminal.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open PTY: %w", err)
	}
	defer ptmx.Close()

	// Mirror the current terminal size into the PTY.
	if cols, rows, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
		_ = pty.Setsize(ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
	}

	// Raw mode so every keystroke (including password input) is forwarded as-is.
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", 0, fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Forward keyboard input to the PTY master.
	go io.Copy(ptmx, os.Stdin)

	// Read PTY output, show it on the terminal and capture it simultaneously.
	var buf bytes.Buffer
	io.Copy(io.MultiWriter(&bestEffort{w: os.Stdout}, &buf), ptmx) // blocks until subprocess exits

	return buf.String(), exitStatus(cmd.Wait()), nil
}

// bestEffort shows output while it can: after the first failed write (the
// terminal or the reader of a pipe went away) it drops the rest, so the
// capture goes on.
type bestEffort struct {
	w      io.Writer
	failed bool
}

func (b *bestEffort) Write(p []byte) (int, error) {
	if !b.failed {
		if _, err := b.w.Write(p); err != nil {
			b.failed = true
		}
	}
	return len(p), nil
}

// lockedBuf is a buffer the stdout and stderr copiers can share.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// exitStatus turns the error from cmd.Wait into the exit status a shell
// would report: the command's own code, or 128+N when signal N killed it.
// sameID reports whether a and b are the same UUID, ignoring the spellings
// the server accepts too (letter case, braces, a urn:uuid: prefix, no dashes).
func sameID(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "urn:uuid:")
		return strings.ReplaceAll(strings.Trim(s, "{}"), "-", "")
	}
	return b != "" && norm(a) == norm(b)
}

func exitStatus(err error) int {
	var ee *exec.ExitError
	if err == nil {
		return 0
	}
	if !errors.As(err, &ee) {
		return 1
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ee.ExitCode()
}

// pipeResult is the server's answer to POST /api/v1/pipe.
type pipeResult struct {
	Error          string `json:"error"`
	HostIdentifier string `json:"host_identifier"`
	AssessmentID   string `json:"assessment_id"`
	AssessmentName string `json:"assessment_name"`
	Bytes          int    `json:"bytes"`
	Candidates     []struct {
		HostIdentifier string `json:"host_identifier"`
		AssessmentID   string `json:"assessment_id"`
		AssessmentName string `json:"assessment_name"`
	} `json:"candidates"`
}

// upload sends the output to the server. A nil error means the server saved
// it; any other outcome is an error, so the caller keeps the output.
func upload(cfg config, body map[string]string) (pipeResult, error) {
	var result pipeResult
	resp, err := apiPost(cfg.URL+"/api/v1/pipe", cfg.Token, body)
	if err != nil {
		return result, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	decodeErr := decodeJSON(resp.Body, &result)

	switch {
	case resp.StatusCode == http.StatusCreated:
		return result, nil
	case resp.StatusCode == http.StatusUnauthorized:
		return result, errors.New("session expired — run `pk login` to authenticate again")
	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		return result, fmt.Errorf("the output (%d bytes) is larger than the server accepts", len(body["output"]))
	case decodeErr != nil || result.Error == "":
		return result, fmt.Errorf("unexpected response from server (HTTP %d) — check the URL in %s", resp.StatusCode, configPath())
	case resp.StatusCode == http.StatusConflict && len(result.Candidates) > 0:
		return result, fmt.Errorf("%q is a host in several assessments; choose one with --assessment <name or id>", body["target"])
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusConflict:
		return result, errors.New(result.Error)
	default:
		return result, fmt.Errorf("server error (HTTP %d): %s", resp.StatusCode, result.Error)
	}
}

// uploadOrInterrupt is upload, except that Ctrl-C (or SIGTERM) while it
// waits on the server returns an error at once, so the output is still kept
// when the user gives up on a slow upload.
func uploadOrInterrupt(cfg config, body map[string]string) (pipeResult, error) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	type answer struct {
		result pipeResult
		err    error
	}
	done := make(chan answer, 1)
	go func() {
		result, err := upload(cfg, body)
		done <- answer{result, err}
	}()
	select {
	case a := <-done:
		return a.result, a.err
	case s := <-sig:
		return pipeResult{}, fmt.Errorf("interrupted (%v) before the server answered", s)
	}
}

// unsentDir is where output that could not be uploaded is kept:
// $XDG_STATE_HOME/pk/unsent, else ~/.local/state/pk/unsent.
func unsentDir() (string, error) {
	if dir := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(dir) {
		return filepath.Join(dir, "pk", "unsent"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "pk", "unsent"), nil
}

var unsafeFileChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// unsentPattern is the os.CreateTemp pattern for output kept for target:
// a timestamp, then the target and tool made safe for a file name.
func unsentPattern(now time.Time, target, tool string) string {
	clean := func(s string, max int) string {
		s = strings.Trim(unsafeFileChars.ReplaceAllString(s, "_"), "._")
		if len(s) > max {
			s = s[:max]
		}
		return s
	}
	return now.Format("20060102-150405") + "-" + clean(target, 64) + "-" + clean(tool, 32) + "-*.txt"
}

// saveUnsent writes output to a new private file and returns its path.
func saveUnsent(target, tool, output string) (string, error) {
	dir, err := unsentDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, unsentPattern(time.Now(), target, tool)) // mode 0600
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(output); err != nil {
		_ = f.Close()
		return "", err
	}
	return f.Name(), f.Close()
}

var shellSpecial = regexp.MustCompile(`[^A-Za-z0-9@%+=:,./_-]`)

// shellQuote quotes s for a POSIX shell when it needs it.
func shellQuote(s string) string {
	if s != "" && !shellSpecial.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// resendCommand is the pk command line that sends the file at path again.
func resendCommand(target, assessment, tool, command, path string) string {
	args := []string{"pk", "--target", shellQuote(target)}
	if assessment != "" {
		args = append(args, "--assessment", shellQuote(assessment))
	}
	args = append(args, "--tool", shellQuote(tool))
	if command != "" {
		args = append(args, "--command", shellQuote(command))
	}
	return strings.Join(append(args, "<", shellQuote(path)), " ")
}

// cmdPipe captures the output, uploads it and returns pk's exit status: the
// command's own with --run, and non-zero whenever the output was not saved
// on the server, in which case it is kept in a local file instead.
func cmdPipe(target, assessment, tool, command, run string) (int, error) {
	cfg, err := loadConfig()
	if err != nil {
		return 1, fmt.Errorf("not logged in — run `pk login` first")
	}
	if cfg.Token == "" {
		return 1, fmt.Errorf("no token found — run `pk login` first")
	}

	var output string
	status := 0
	if run != "" {
		// --run mode: execute the command ourselves so stdin stays a TTY.
		output, status, err = runCapture(run)
		if err != nil {
			return 1, fmt.Errorf("command failed: %w", err)
		}
		if command == "" {
			command = run
		}
	} else {
		// Pipe mode: read from stdin as before.
		data, err := io.ReadAll(bufio.NewReader(os.Stdin))
		output = string(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] failed to read stdin: %s\n", err)
			status = 1
		}
	}

	if tool == "" {
		src := command
		if src == "" {
			src = run
		}
		if fields := strings.Fields(src); len(fields) > 0 {
			tool = filepath.Base(fields[0])
		} else {
			tool = "unknown"
		}
	}
	if status != 0 && run != "" {
		defer fmt.Fprintf(os.Stderr, "[!] The command exited with status %d\n", status)
	}

	body := map[string]string{
		"target":  target,
		"tool":    tool,
		"command": command,
		"output":  output,
	}
	if assessment != "" {
		body["assessment"] = assessment
	}
	result, err := uploadOrInterrupt(cfg, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Not saved on the server: %s\n", err)
		for _, c := range result.Candidates {
			fmt.Fprintf(os.Stderr, "      %s in %q (id %s)\n", c.HostIdentifier, c.AssessmentName, c.AssessmentID)
		}
		if status == 0 {
			status = 1
		}
		path, serr := saveUnsent(target, tool, output)
		if serr != nil {
			fmt.Fprintf(os.Stderr, "[!] Could not keep the output in a file either (%s); here it is:\n", serr)
			_, _ = os.Stdout.WriteString(output)
			return status, nil
		}
		fmt.Fprintf(os.Stderr, "[*] Output kept in %s\n", path)
		if len(result.Candidates) > 0 {
			assessment = "<name or id>"
		}
		fmt.Fprintf(os.Stderr, "[*] To send it again: %s\n", resendCommand(target, assessment, tool, command, path))
		return status, nil
	}

	fmt.Printf("[+] Saved to host %s (%s) — %d bytes\n", result.HostIdentifier, result.AssessmentName, result.Bytes)
	// A server older than this pk ignores --assessment and may match a
	// host whose identifier only contains the target.
	if result.HostIdentifier != "" {
		otherHost := !strings.EqualFold(result.HostIdentifier, target)
		otherAssessment := assessment != "" && assessment != result.AssessmentName && !sameID(assessment, result.AssessmentID)
		switch {
		case otherHost || otherAssessment && result.AssessmentID != "":
			fmt.Fprintln(os.Stderr, "[!] That is not the host or assessment you named; the server may be older than this pk")
			if status == 0 {
				status = 1
			}
		case otherAssessment:
			// An older server reports no assessment id, so an id given to
			// --assessment cannot be confirmed.
			fmt.Fprintln(os.Stderr, "[*] This server is too old to confirm the assessment; check the host in the web UI")
		}
	}
	return status, nil
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func usage() {
	fmt.Fprintf(os.Stderr, `pk — Penkeeper CLI

Usage:
  pk login                              Authenticate and save credentials
  <tool> | pk --target <ip> [flags]    Pipe tool output to a host
  pk --target <ip> --run "<cmd>"       Run a command and capture its output

Flags:
  --target     <ip/host>  Host identifier to attach output to (required);
                          matched exactly, ignoring case
  --assessment <name|id>  Assessment the host is in, when the identifier is
                          a host in several assessments
  --tool       <name>     Tool name tag (default: derived from command)
  --command    <cmd>      Command string for record-keeping (pipe mode)
  --run        <cmd>      Run this shell command directly; stdin stays a TTY
                          so interactive prompts (e.g. smbclient credentials)
                          work normally. Its stdout and stderr are shown on
                          pk's stdout and stderr and both captured, and pk
                          exits with its status.

Output the server does not save (expired session, unknown host, network
error...) is kept in $XDG_STATE_HOME/pk/unsent (default
~/.local/state/pk/unsent), and pk prints how to send it again.

Examples:
  pk login
  whatweb http://192.168.1.1 | pk --target 192.168.1.1 --tool whatweb
  pk --target 192.168.1.1 --run "smbclient //192.168.1.1/share"
  pk --target 192.168.1.1 --run "smbclient //192.168.1.1/share -U admin"
`)
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	if args[0] == "login" {
		if err := cmdLogin(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
		return
	}

	if args[0] == "--help" || args[0] == "-h" {
		usage()
		return
	}

	// Pipe / run mode — parse flags
	var target, assessment, tool, command, run string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--target":
			if i+1 < len(args) {
				target = args[i+1]
				i++
			}
		case "--assessment":
			if i+1 < len(args) {
				assessment = args[i+1]
				i++
			}
		case "--tool":
			if i+1 < len(args) {
				tool = args[i+1]
				i++
			}
		case "--command":
			if i+1 < len(args) {
				command = args[i+1]
				i++
			}
		case "--run":
			if i+1 < len(args) {
				run = args[i+1]
				i++
			}
		}
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "[!] --target is required")
		usage()
		os.Exit(1)
	}

	status, err := cmdPipe(target, assessment, tool, command, run)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
	}
	os.Exit(status)
}
