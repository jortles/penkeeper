// internal/model/models.go
package model

import (
	"time"

	"github.com/google/uuid"
)

// -------------------------------------------------------------------
// User – an account that can sign in
// -------------------------------------------------------------------
type User struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	Email       string    `gorm:"uniqueIndex;size:255" json:"email"`
	Password    string    `json:"-"`                   // never expose the hash
	Role        string    `gorm:"size:32" json:"role"` // e.g. "admin" or "user"
	TOTPSecret  string    `json:"-"`                   // base32 TOTP shared secret
	TOTPEnabled bool      `json:"totp_enabled"`
	// TokenVersion is embedded in issued JWTs and checked on every request.
	// Incrementing it (e.g. on password reset) invalidates all prior sessions.
	TokenVersion int `gorm:"not null;default:0" json:"-"`
	// TOTPLastCounter is the most recent TOTP time-step consumed at login,
	// used to reject replay of a code within its validity window.
	TOTPLastCounter int64     `gorm:"not null;default:0" json:"-"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// -------------------------------------------------------------------
// PasswordResetToken – time-limited single-use token for password reset
// -------------------------------------------------------------------
type PasswordResetToken struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;index"`
	TokenHash string    `gorm:"size:64;uniqueIndex"` // SHA-256 hex of raw token (token itself is only sent by email)
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// -------------------------------------------------------------------
// Assessment – a pentest assessment
// -------------------------------------------------------------------
type Assessment struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	OwnerID    uuid.UUID `gorm:"type:uuid;index" json:"owner_id"`
	Name       string    `gorm:"size:200;not null" json:"name"`
	ScratchPad string    `gorm:"type:text" json:"scratch_pad"` // free-form assessment-level notes
	// ScratchPadVersion is incremented on every scratch pad save. The client
	// sends the version it loaded, so a stale copy gets a 409 instead of
	// overwriting newer text. ScratchPadSaveID is the client-chosen id of the
	// save that wrote the current text ("" when none was sent), like
	// Note.SaveID.
	ScratchPadVersion int       `gorm:"not null;default:0" json:"scratch_pad_version"`
	ScratchPadSaveID  string    `gorm:"size:64;not null;default:''" json:"-"`
	SortOrder         int       `json:"sort_order"` // user-defined display order
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`

	Hosts []Host `gorm:"constraint:OnDelete:CASCADE;" json:"hosts"` // eager‑loadable
}

// -------------------------------------------------------------------
// Host – a target host inside an assessment
// -------------------------------------------------------------------
type Host struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	AssessmentID uuid.UUID `gorm:"type:uuid;index" json:"assessment_id"`

	Identifier  string `json:"identifier"` // IP, CIDR, hostname, FQDN (one per line)
	Label       string `json:"label"`
	DeviceType  string `json:"device_type"` // server / laptop / desktop …
	OS          string `json:"os"`          // Windows, Linux, macOS, …
	Compromised bool   `json:"compromised"` // marked as compromised (skull flag)

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Child collections – all optional, but we expose them for the UI
	Ports       []Port       `gorm:"constraint:OnDelete:CASCADE;" json:"ports"`
	Creds       []Credential `gorm:"constraint:OnDelete:CASCADE;" json:"creds,omitempty"`
	Notes       []Note       `gorm:"constraint:OnDelete:CASCADE;" json:"notes,omitempty"`
	ToolOutputs []ToolOutput `gorm:"constraint:OnDelete:CASCADE;" json:"tool_outputs,omitempty"`
}

// -------------------------------------------------------------------
// Port – a scanned/open port belonging to a host
// -------------------------------------------------------------------
type Port struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	HostID       uuid.UUID `gorm:"type:uuid;index" json:"host_id"`
	Number       uint16    `json:"number"`            // 1‑65535 (0-255 for protocol "ip")
	Protocol     string    `json:"protocol"`          // "tcp", "udp", "sctp" or "ip"
	Service      string    `json:"service,omitempty"` // optional banner / service name
	Info         string    `gorm:"type:text" json:"info,omitempty"`
	ScriptOutput string    `gorm:"type:text" json:"script_output,omitempty"` // JSON array of {id, output} from -sC
	CreatedAt    time.Time `json:"created_at"`
	// ServiceEdited and InfoEdited mark a Service or Info value the user typed
	// (Add Port, Edit Port). Nmap imports keep such a value instead of the
	// scanned one; they still fill the field once it is empty, and NSE script
	// output always merges.
	ServiceEdited bool `gorm:"not null;default:false" json:"service_edited"`
	InfoEdited    bool `gorm:"not null;default:false" json:"info_edited"`
}

// -------------------------------------------------------------------
// Credential – a discovered username/password pair for a host
// -------------------------------------------------------------------
type Credential struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	HostID    uuid.UUID `gorm:"type:uuid;index" json:"host_id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"` // AES-256-GCM encrypted at rest
	Hash      string    `json:"hash"`     // e.g. NTLM hash, bcrypt, etc. (stored plaintext)
	Source    string    `json:"source"`   // e.g. "manual", "nmap", "import"
	CreatedAt time.Time `json:"created_at"`
}

// -------------------------------------------------------------------
// Command – a command reference; may be global (HostID nil) or tied to a host
// -------------------------------------------------------------------
type Command struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;index" json:"user_id"`
	HostID    *uuid.UUID `gorm:"type:uuid;index" json:"host_id,omitempty"`
	OS        string     `json:"os"`
	Category  string     `json:"category"`
	Name      string     `json:"name"`
	Command   string     `gorm:"type:text" json:"command"`
	Notes     string     `gorm:"type:text" json:"notes"`
	CreatedAt time.Time  `json:"created_at"`
}

// -------------------------------------------------------------------
// Note – a text note file belonging to a host
// -------------------------------------------------------------------
type Note struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	HostID    uuid.UUID `gorm:"type:uuid;index" json:"host_id"`
	Title     string    `json:"title"`
	Content   string    `gorm:"type:text" json:"content"`
	SortOrder int       `json:"sort_order"` // user-defined display order
	// Version is incremented on every title/content update. The editor sends
	// the version it loaded, so a stale copy gets a 409 instead of
	// overwriting newer text. SaveID is the client-chosen id of the save that
	// wrote the current title/content ("" when none was sent): a client whose
	// reply got lost names it in its next save, which then applies on top of
	// that write instead of conflicting with it.
	Version   int       `gorm:"not null;default:0" json:"version"`
	SaveID    string    `gorm:"size:64;not null;default:''" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// -------------------------------------------------------------------
// ToolOutput – raw stdout from an external tool piped into the app
// -------------------------------------------------------------------
type ToolOutput struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	HostID    uuid.UUID `gorm:"type:uuid;index"      json:"host_id"`
	Tool      string    `json:"tool"`              // e.g. "whatweb", "crackmapexec"
	Command   string    `json:"command,omitempty"` // full command that was run
	Output    string    `gorm:"type:text" json:"output"`
	CreatedAt time.Time `json:"created_at"`
}

// -------------------------------------------------------------------
// ActivityLog – records significant events within an assessment
// -------------------------------------------------------------------
type ActivityLog struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	AssessmentID uuid.UUID `gorm:"type:uuid;index"      json:"assessment_id"`
	ActorEmail   string    `json:"actor_email"`
	Action       string    `json:"action"` // e.g. "host_added", "nmap_scan", "credential_added"
	Detail       string    `json:"detail"` // human-readable sentence
	CreatedAt    time.Time `json:"created_at"`
}

// -------------------------------------------------------------------
// RevokedToken – a session token ended by Logout before it expired
// -------------------------------------------------------------------
// JWTAuth refuses a token whose jti claim is listed here. Rows are kept
// until ExpiresAt (the token's own expiry) and purged after that.
type RevokedToken struct {
	JTI       string    `gorm:"column:jti;size:64;primaryKey"`
	ExpiresAt time.Time `gorm:"not null;index"`
}
