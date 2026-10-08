package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	assets "penkeeper"
	"penkeeper/internal/api"
	appcrypto "penkeeper/internal/crypto"
	"penkeeper/internal/email"
	"penkeeper/internal/middleware"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func printDBSetupInstructions(connErr string) {
	msg := `
================================================================================
  DATABASE CONNECTION FAILED
================================================================================

  Error: %s

  Penkeeper requires a running PostgreSQL instance. Follow the steps below
  to set one up.

  1. Install PostgreSQL (if not already installed)
     -----------------------------------------------
     Debian / Kali / Ubuntu:
       sudo apt update && sudo apt install -y postgresql postgresql-client

     macOS (Homebrew):
       brew install postgresql@16 && brew services start postgresql@16

  2. Start the PostgreSQL service
     -----------------------------------------------
       sudo systemctl start postgresql
       sudo systemctl enable postgresql    # optional: start on boot

  3. Create the database and user
     -----------------------------------------------
       openssl rand -hex 24      # use the output as <db-password> below
       sudo -u postgres psql -c "CREATE USER penkeeper WITH PASSWORD '<db-password>';"
       sudo -u postgres psql -c "CREATE DATABASE penkeeper OWNER penkeeper;"

  4. Set the required configuration
     -----------------------------------------------
     In a .env file in the working directory (one KEY=value per line; it is
     not run through a shell, so paste the generated values themselves):

       DATABASE_URL=postgres://penkeeper:<db-password>@localhost:5432/penkeeper?sslmode=disable
       JWT_SECRET=<output of: openssl rand -hex 32>
       ENCRYPTION_KEY=<output of another: openssl rand -hex 32>

  5. Run the server again
     -----------------------------------------------
       ./server                   # if built as a binary
       go run ./cmd/server        # if running from source

  Tables are created automatically on first successful connection.

================================================================================
`
	fmt.Printf(msg, connErr)
}

func main() {
	// ------------------------------------------------------------
	// Load a local .env file if present, so `./server` works without
	// requiring the caller to `source .env` first. Real environment
	// variables always take precedence over values in the file.
	// ------------------------------------------------------------
	loadDotEnv(".env")

	// ------------------------------------------------------------
	// Required environment variables
	// ------------------------------------------------------------
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		printDBSetupInstructions("DATABASE_URL environment variable is not set")
		os.Exit(1)
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		fmt.Println(`
================================================================================
  MISSING CONFIGURATION: JWT_SECRET
================================================================================

  The JWT_SECRET environment variable is required for authentication.

  Generate one with:  openssl rand -hex 32
  and put the output in .env (not run through a shell):
    JWT_SECRET=<output>

================================================================================`)
		os.Exit(1)
	}

	// ------------------------------------------------------------
	// Encryption key for credentials / TOTP secrets at rest
	// ------------------------------------------------------------
	encSecret := os.Getenv("ENCRYPTION_KEY")

	// Refuse public, unexpanded or short secrets: a weak HS256 secret lets
	// anyone forge sessions, and a weak at-rest key exposes stored credentials.
	refusal, warnings := checkSecrets(jwtSecret, encSecret, os.Getenv("PK_ALLOW_INSECURE_SECRETS"))
	if refusal != "" {
		fmt.Println(refusal)
		os.Exit(1)
	}
	for _, w := range warnings {
		log.Printf("WARNING: PK_ALLOW_INSECURE_SECRETS is set — %s", w)
	}

	if encSecret == "" {
		encSecret = jwtSecret // fallback: derive from JWT secret
		log.Printf("WARNING: ENCRYPTION_KEY is not set — deriving the at-rest encryption " +
			"key from JWT_SECRET. Set ENCRYPTION_KEY explicitly: leaking JWT_SECRET would " +
			"then also expose stored credentials, and rotating JWT_SECRET would make all " +
			"encrypted data undecryptable.")
	}
	appcrypto.Init([]byte(encSecret))

	// ------------------------------------------------------------
	// DB connection
	// ------------------------------------------------------------
	db, err := storage.NewPostgres(dsn)
	if errors.Is(err, storage.ErrForeignDB) {
		log.Fatalf("%v, so penkeeper will not start. Penkeeper keeps its data in its own database: "+
			"put penkeeper's DATABASE_URL in .env and unset DATABASE_URL in this shell (an exported variable overrides .env).", err)
	}
	if err != nil {
		errMsg := err.Error()
		// Provide specific hints for common failures
		if strings.Contains(errMsg, "connection refused") {
			printDBSetupInstructions("Connection refused — is PostgreSQL running? (sudo systemctl start postgresql)")
		} else if strings.Contains(errMsg, "password authentication failed") {
			printDBSetupInstructions("Password authentication failed — check your DATABASE_URL credentials")
		} else if strings.Contains(errMsg, "does not exist") {
			printDBSetupInstructions("Database or role does not exist — see step 3 above to create them")
		} else {
			printDBSetupInstructions(errMsg)
		}
		os.Exit(1)
	}
	api.PrepareCredentialStore(db)

	// ------------------------------------------------------------
	// First-launch setup: create admin if no users exist
	// ------------------------------------------------------------
	var userCount int64
	db.Model(&model.User{}).Count(&userCount)
	if userCount == 0 {
		if err := createFirstAdmin(db); err != nil {
			log.Fatalf("First-launch setup failed: %v", err)
		}
	}

	// ------------------------------------------------------------
	// Gin router
	// ------------------------------------------------------------
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode) // suppress debug output unless explicitly overridden
	}
	// gin.New instead of gin.Default: gin's own access log records query
	// strings (password-reset tokens); middleware.Logger logs the path only.
	r := gin.New()
	r.Use(gin.Recovery())
	// Do not trust any proxy headers by default. Without this, gin's ClientIP()
	// honors a client-supplied X-Forwarded-For, letting an attacker rotate that
	// header to bypass the per-IP rate limiter on the auth endpoints. Operators
	// running behind a real reverse proxy should set TRUSTED_PROXIES.
	if tp := os.Getenv("TRUSTED_PROXIES"); strings.TrimSpace(tp) != "" {
		var proxies []string
		for _, p := range strings.Split(tp, ",") {
			if p = strings.TrimSpace(p); p != "" { // skip blanks from stray commas
				proxies = append(proxies, p)
			}
		}
		if err := r.SetTrustedProxies(proxies); err != nil {
			log.Fatalf("invalid TRUSTED_PROXIES: %v", err)
		}
		if os.Getenv("APP_URL") == "" {
			log.Printf("WARNING: TRUSTED_PROXIES is set but APP_URL is not. Set APP_URL to the URL users " +
				"open (e.g. https://penkeeper.example.com): password-reset links use it, and unless the proxy " +
				"sends X-Forwarded-Proto and X-Forwarded-Host, browsers on plain HTTP get 403 on login.")
		}
	} else if err := r.SetTrustedProxies(nil); err != nil {
		log.Fatalf("failed to disable trusted proxies: %v", err)
	}
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.Logger())
	r.Use(middleware.CSRFProtect(os.Getenv("APP_URL")))
	// Cap request bodies before any handler reads them. Routes not listed
	// here (plain JSON) get 1 MB.
	const largeText = 20 << 20 // notes, scratch pad
	// Tool output itself is limited to 20 MB by its handlers; its body cap
	// leaves room for JSON escaping (quotes, newlines, backslashes double).
	const toolBody = 2 * largeText
	r.Use(middleware.BodyLimit(1<<20, map[string]int64{
		"/api/auth/":                          64 << 10,
		"/api/v1/pipe":                        toolBody,
		"/api/v1/hosts/:hid/outputs":          toolBody,
		"/api/v1/hosts/:hid/notes":            largeText,
		"/api/v1/hosts/:hid/notes/:nid":       largeText,
		"/api/v1/assessments/:eid/scratchpad": largeText,
		"/api/v1/import":                      50 << 20,        // Import's own cap
		"/api/v1/hosts/:hid/nmap":             10<<20 + 64<<10, // 10 MB file + multipart framing
		"/api/v1/assessments/:eid/nmap":       10<<20 + 64<<10,
	}))

	// ------------------------------------------------------------
	// SMTP / email config for password reset
	// ------------------------------------------------------------
	port := os.Getenv("PORT")
	if port == "" {
		port = "1338"
	}
	emailCfg := email.Config{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     coalesce(os.Getenv("SMTP_PORT"), "587"),
		User:     os.Getenv("SMTP_USER"),
		Password: os.Getenv("SMTP_PASS"),
		From:     coalesce(os.Getenv("SMTP_FROM"), os.Getenv("SMTP_USER")),
	}
	appURL := coalesce(os.Getenv("APP_URL"), "http://localhost:"+port)

	// ------------------------------------------------------------
	// Auth routes (no JWT required)
	// ------------------------------------------------------------
	if err := api.MigrateAuth(db); err != nil {
		log.Fatalf("auth migration failed: %v", err)
	}
	authGrp := r.Group("/api/auth")
	authGrp.Use(middleware.RateLimit(10, 1*time.Minute)) // 10 attempts per minute per IP
	authGrp.POST("/login", api.Login(db, jwtSecret))
	authGrp.POST("/totp", api.TOTPLogin(db, jwtSecret)) // step-2 TOTP verification
	// Password reset
	authGrp.POST("/forgot-password", api.ForgotPassword(db, emailCfg, appURL))
	authGrp.POST("/reset-password/validate", api.ValidateResetToken(db))
	authGrp.GET("/reset-password", api.ValidateResetToken(db)) // older pages: token in the query string
	authGrp.POST("/reset-password", api.ResetPassword(db))
	// Logout is not rate limited: a full limiter must never keep a session alive.
	r.POST("/api/auth/logout", api.Logout(db, jwtSecret))

	// ------------------------------------------------------------
	// Protected API group – all routes under /api/v1
	// ------------------------------------------------------------
	apiGrp := r.Group("/api/v1")
	apiGrp.Use(middleware.JWTAuth(db, jwtSecret))

	// Assessment routes
	apiGrp.POST("/assessments", api.CreateAssessment(db))
	apiGrp.GET("/assessments", api.ListAssessments(db))
	apiGrp.GET("/assessments/:eid", api.GetAssessment(db))
	apiGrp.DELETE("/assessments/:eid", api.DeleteAssessment(db))
	apiGrp.POST("/assessments/:eid/nmap", api.BulkImportNmap(db))
	apiGrp.GET("/assessments/:eid/activity", api.ListActivity(db))

	// Host routes
	apiGrp.POST("/assessments/:eid/hosts", api.CreateHost(db))
	apiGrp.GET("/assessments/:eid/hosts", api.ListHosts(db))
	apiGrp.GET("/hosts/:hid", api.GetHost(db))
	apiGrp.POST("/hosts/:hid/ports", api.AddPort(db))
	apiGrp.GET("/hosts/:hid/ports", api.ListPorts(db))
	apiGrp.PUT("/hosts/:hid/ports/:pid", api.UpdatePort(db))
	apiGrp.DELETE("/hosts/:hid/ports/:pid", api.DeletePort(db))
	apiGrp.PUT("/hosts/:hid", api.UpdateHost(db))
	apiGrp.PATCH("/hosts/:hid/compromised", api.SetCompromised(db))
	apiGrp.POST("/hosts/:hid/nmap", api.ImportNmap(db))
	apiGrp.DELETE("/hosts/:hid", api.DeleteHost(db))

	// Credential routes
	apiGrp.POST("/hosts/:hid/credentials", api.AddCredential(db))
	apiGrp.GET("/hosts/:hid/credentials", api.ListCredentials(db))
	apiGrp.GET("/credentials/:cid", api.GetCredential(db))
	apiGrp.PUT("/hosts/:hid/credentials/:cid", api.UpdateCredential(db))
	apiGrp.DELETE("/hosts/:hid/credentials/:cid", api.DeleteCredential(db))

	// Note routes
	apiGrp.POST("/hosts/:hid/notes", api.CreateNote(db))
	apiGrp.GET("/hosts/:hid/notes", api.ListNotes(db))
	apiGrp.GET("/notes/:nid", api.GetNote(db))
	apiGrp.PUT("/hosts/:hid/notes/:nid", api.UpdateNote(db))
	apiGrp.DELETE("/hosts/:hid/notes/:nid", api.DeleteNote(db))
	apiGrp.PUT("/hosts/:hid/notes/:nid/move", api.MoveNote(db))
	apiGrp.PUT("/hosts/:hid/notes/:nid/order", api.UpdateNoteOrder(db))

	// Assessment scratch pad and ordering
	apiGrp.PUT("/assessments/:eid/scratchpad", api.UpdateScratchPad(db))
	apiGrp.PUT("/assessments/:eid/order", api.UpdateAssessmentOrder(db))

	// Tool output (Services tab) + CLI pipe endpoint
	apiGrp.GET("/hosts/:hid/outputs", api.ListToolOutputs(db))
	apiGrp.POST("/hosts/:hid/outputs", api.AddToolOutput(db))
	apiGrp.DELETE("/hosts/:hid/outputs/:oid", api.DeleteToolOutput(db))
	apiGrp.POST("/pipe", api.PipeInput(db))

	// Admin routes
	apiGrp.GET("/admin/users", api.ListUsers(db))

	// Settings / TOTP routes
	apiGrp.GET("/settings/me", api.GetMe(db))
	apiGrp.POST("/settings/totp/setup", api.SetupTOTP(db, "Penkeeper"))
	apiGrp.POST("/settings/totp/enable", api.EnableTOTP(db, jwtSecret))
	apiGrp.DELETE("/settings/totp", api.DisableTOTP(db, jwtSecret))

	// Command routes (global – not tied to assessments/hosts)
	apiGrp.POST("/commands", api.CreateCommand(db))
	apiGrp.GET("/commands", api.ListCommands(db))
	apiGrp.GET("/commands/:cid", api.GetCommand(db))
	apiGrp.PUT("/commands/:cid", api.UpdateCommand(db))
	apiGrp.DELETE("/commands/:cid", api.DeleteCommand(db))

	// Host-scoped command routes
	apiGrp.GET("/hosts/:hid/commands", api.ListHostCommands(db))
	apiGrp.POST("/hosts/:hid/commands", api.CreateHostCommand(db))
	apiGrp.PUT("/hosts/:hid/commands/:cid", api.UpdateHostCommand(db))
	apiGrp.DELETE("/hosts/:hid/commands/:cid", api.DeleteHostCommand(db))

	// Port routes
	apiGrp.GET("/ports/:pid", api.GetPort(db))
	apiGrp.GET("/assessments/:eid/ports", api.ListAssessmentPorts(db))
	apiGrp.GET("/search", api.Search(db))

	apiGrp.GET("/export", api.Export(db))
	// An encrypted 50 MB import peaks at roughly 260 MB of memory; bound how
	// many run at once.
	apiGrp.POST("/import", middleware.MaxInFlight(2), api.Import(db))

	// ------------------------------------------------------------
	// Serve static front-end (embedded at build time)
	// ------------------------------------------------------------
	subFS, err := fs.Sub(assets.FrontendFS, "frontend")
	if err != nil {
		log.Fatalf("failed to mount embedded frontend: %v", err)
	}
	httpFS := http.FS(subFS)
	r.StaticFS("/static", httpFS)

	indexHTML, err := fs.ReadFile(subFS, "index.html")
	if err != nil {
		log.Fatalf("failed to read embedded index.html: %v", err)
	}

	serveIndex := func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexHTML)
	}
	r.GET("/", serveIndex)
	r.NoRoute(serveIndex)

	// ------------------------------------------------------------
	// Run the server
	// ------------------------------------------------------------
	addr := ":" + port
	srv := &http.Server{
		Addr:              addr,
		Handler:           r.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,  // a 50 MB import over a slow VPN
		WriteTimeout:      10 * time.Minute, // large exports and Nmap imports
		IdleTimeout:       2 * time.Minute,
	}
	log.Printf("Server listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// loadDotEnv reads a simple KEY=VALUE .env file and sets any variables that
// are not already present in the process environment. It silently does nothing
// if the file is absent. Supports `#` comments, blank lines, `export KEY=...`
// prefixes, and single/double quoted values. Existing env vars always win.
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // no .env file — rely on the real environment
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		// Strip matching surrounding quotes.
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if key != "" {
			if _, exists := os.LookupEnv(key); !exists {
				os.Setenv(key, val)
			}
		}
	}
}

// coalesce returns the first non-empty string argument.
func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// createFirstAdmin interactively prompts for an email and password to create
// the initial admin account when no users exist in the database.
func createFirstAdmin(db *storage.DB) error {
	fmt.Print(`
================================================================================
  FIRST LAUNCH SETUP
================================================================================

  No users found. Create an admin account to get started.

`)

	reader := bufio.NewReader(os.Stdin)

	// --- Email ---
	fmt.Print("  Email: ")
	emailInput, _ := reader.ReadString('\n')
	emailInput = strings.TrimSpace(emailInput)
	if !strings.Contains(emailInput, "@") || !strings.Contains(emailInput, ".") {
		return fmt.Errorf("invalid email address: %q", emailInput)
	}

	// --- Password (masked when running in a terminal) ---
	var password string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("  Password (min 8 chars): ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Print("  Confirm password: ")
		pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		if string(pw) != string(pw2) {
			return fmt.Errorf("passwords do not match")
		}
		password = string(pw)
	} else {
		// Non-interactive (pipe/script) — read plaintext
		fmt.Print("  Password (min 8 chars): ")
		pw, _ := reader.ReadString('\n')
		password = strings.TrimSpace(pw)
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user := model.User{
		ID:       uuid.New(),
		Email:    emailInput,
		Password: string(hash),
		Role:     "admin",
	}
	if err := db.Create(&user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Printf("\n  Admin account created: %s\n", emailInput)
	fmt.Println("================================================================================")
	fmt.Println()
	return nil
}
