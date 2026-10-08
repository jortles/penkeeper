package api

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/scrypt"
	"gorm.io/gorm"

	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// exportVersion is the current bundle format. Import also accepts older
// bundles (see the version check in Import).
const exportVersion = 2

// importMaxBytes is the largest bundle Import accepts. Export refuses to
// produce a larger one, so every export can be restored.
const importMaxBytes = 50 << 20

// bundleTooLargeMsg is the message for a bundle over importMaxBytes.
var bundleTooLargeMsg = fmt.Sprintf("bundle too large: the import limit is %d MB", importMaxBytes>>20)

// ---------------------------------------------------------------------------
// Bundle-level encryption.
//
// Encrypted exports use envelope format pne_enc: 2. The key is derived from a
// user-supplied passphrase via scrypt with a per-file random salt.
//
// The export always contains plaintext credential passwords and hashes (so it
// can be imported to an installation with a different at-rest key), so an
// encrypted export is the only way to protect them in transit/at rest.
// ---------------------------------------------------------------------------

// scrypt parameters (N=32768, r=8, p=1) — interactive-grade, ~tens of ms.
const (
	scryptN       = 1 << 15
	scryptR       = 8
	scryptP       = 1
	scryptKeyLen  = 32
	bundleSaltLen = 16
)

// encEnvelope is the JSON structure written to encrypted .pne files.
// Using a JSON wrapper (rather than a binary magic prefix) ensures the file
// is always valid text and is handled correctly by all multipart stacks.
type encEnvelope struct {
	PNEEnc int    `json:"pne_enc"`        // format version: 2 (passphrase)
	Salt   string `json:"salt,omitempty"` // base64 scrypt salt (v2 only)
	Data   string `json:"data"`           // base64(nonce + AES-GCM ciphertext)
}

// deriveBundleKey stretches a user passphrase into a 32-byte AES key via scrypt.
func deriveBundleKey(passphrase string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
}

func aesGCMSeal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesGCMOpen(key, raw []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	plaintext, err := gcm.Open(nil, raw[:nonceSize], raw[nonceSize:], nil)
	if err != nil {
		return nil, errors.New("decryption failed — wrong passphrase or corrupted file")
	}
	return plaintext, nil
}

// encryptBundle produces a v2 (passphrase) envelope.
func encryptBundle(data []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, bundleSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key, err := deriveBundleKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	ct, err := aesGCMSeal(key, data)
	if err != nil {
		return nil, err
	}
	env := encEnvelope{
		PNEEnc: 2,
		Salt:   base64.StdEncoding.EncodeToString(salt),
		Data:   base64.StdEncoding.EncodeToString(ct),
	}
	return json.Marshal(env)
}

// decryptBundle decrypts a v2 (passphrase) envelope.
func decryptBundle(data []byte, passphrase string) ([]byte, error) {
	var env encEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, errors.New("not a valid encrypted bundle")
	}
	raw, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	switch env.PNEEnc {
	case 2:
		if passphrase == "" {
			return nil, errors.New("this bundle is encrypted — a passphrase is required")
		}
		salt, err := base64.StdEncoding.DecodeString(env.Salt)
		if err != nil || len(salt) == 0 {
			return nil, errors.New("invalid or missing salt in encrypted bundle")
		}
		key, err := deriveBundleKey(passphrase, salt)
		if err != nil {
			return nil, err
		}
		return aesGCMOpen(key, raw)
	default:
		return nil, fmt.Errorf("unsupported encryption format %d: export the data again with a passphrase", env.PNEEnc)
	}
}

// ---------------------------------------------------------------------------
// Export wire types — credential passwords and hashes are stored as plaintext
// so the bundle is usable after import to an installation with a different key.
// ---------------------------------------------------------------------------

type exportPort struct {
	Number        uint16    `json:"number"`
	Protocol      string    `json:"protocol"`
	Service       string    `json:"service,omitempty"`
	Info          string    `json:"info,omitempty"`
	ScriptOutput  string    `json:"script_output,omitempty"`
	ServiceEdited bool      `json:"service_edited,omitempty"` // absent in older bundles
	InfoEdited    bool      `json:"info_edited,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// editFlags returns the port's ServiceEdited and InfoEdited; only a
// non-empty value is marked.
func (ep exportPort) editFlags() (service, info bool) {
	return ep.ServiceEdited && hasValue(ep.Service), ep.InfoEdited && hasValue(ep.Info)
}

type exportCredential struct {
	Username  string    `json:"username"`
	Password  string    `json:"password"`       // plaintext
	Hash      string    `json:"hash,omitempty"` // plaintext
	Source    string    `json:"source,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type exportNote struct {
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	SortOrder int       `json:"sort_order"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type exportToolOutput struct {
	Tool      string    `json:"tool"`
	Command   string    `json:"command,omitempty"`
	Output    string    `json:"output"`
	CreatedAt time.Time `json:"created_at"`
}

type exportHost struct {
	Identifier  string             `json:"identifier"`
	Label       string             `json:"label,omitempty"`
	DeviceType  string             `json:"device_type,omitempty"`
	OS          string             `json:"os,omitempty"`
	Compromised bool               `json:"compromised,omitempty"` // absent in older bundles
	CreatedAt   time.Time          `json:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at"`
	Ports       []exportPort       `json:"ports"`
	Credentials []exportCredential `json:"credentials"`
	Notes       []exportNote       `json:"notes"`
	ToolOutputs []exportToolOutput `json:"tool_outputs"`
	Commands    []exportCommand    `json:"commands,omitempty"`
}

type exportAssessment struct {
	Name       string       `json:"name"`
	Type       string       `json:"type,omitempty"` // penkeeper writes none, see imported
	ScratchPad string       `json:"scratch_pad,omitempty"`
	SortOrder  int          `json:"sort_order"`
	CreatedAt  time.Time    `json:"created_at"`
	UpdatedAt  time.Time    `json:"updated_at"`
	Hosts      []exportHost `json:"hosts"`
}

type exportCommand struct {
	OS        string    `json:"os"`
	Category  string    `json:"category"`
	Name      string    `json:"name"`
	Command   string    `json:"command"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type exportBundle struct {
	Version     int                `json:"version"`
	ExportedAt  time.Time          `json:"exported_at"`
	Assessments []exportAssessment `json:"assessments"`
	Commands    []exportCommand    `json:"commands"`
}

// ---------------------------------------------------------------------------
// Export – GET /api/v1/export
// ---------------------------------------------------------------------------

func Export(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		bundle := exportBundle{
			Version:    exportVersion,
			ExportedAt: time.Now().UTC(),
		}

		var assessments []model.Assessment
		err := db.Where("owner_id = ?", userID).
			Preload("Hosts.Ports").
			Preload("Hosts.Creds").
			Preload("Hosts.Notes").
			Preload("Hosts.ToolOutputs").
			Order("sort_order, created_at").
			Find(&assessments).Error
		if err != nil {
			log.Printf("Export: load assessments: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export data"})
			return
		}

		var allHostCmds []model.Command
		if err := db.Where("user_id = ? AND host_id IS NOT NULL", userID).
			Order("created_at").Find(&allHostCmds).Error; err != nil {
			log.Printf("Export: load host commands: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export data"})
			return
		}
		hostCmdMap := make(map[uuid.UUID][]model.Command)
		for _, cmd := range allHostCmds {
			if cmd.HostID != nil {
				hostCmdMap[*cmd.HostID] = append(hostCmdMap[*cmd.HostID], cmd)
			}
		}

		undecryptable := 0
		for _, a := range assessments {
			ea := exportAssessment{
				Name:       a.Name,
				ScratchPad: a.ScratchPad,
				SortOrder:  a.SortOrder,
				CreatedAt:  a.CreatedAt,
				UpdatedAt:  a.UpdatedAt,
			}
			for _, h := range a.Hosts {
				eh := exportHost{
					Identifier:  h.Identifier,
					Label:       h.Label,
					DeviceType:  h.DeviceType,
					OS:          h.OS,
					Compromised: h.Compromised,
					CreatedAt:   h.CreatedAt,
					UpdatedAt:   h.UpdatedAt,
				}
				for _, p := range h.Ports {
					eh.Ports = append(eh.Ports, exportPort{
						Number: p.Number, Protocol: p.Protocol,
						Service: p.Service, Info: p.Info,
						ScriptOutput:  p.ScriptOutput,
						ServiceEdited: p.ServiceEdited, InfoEdited: p.InfoEdited,
						CreatedAt: p.CreatedAt,
					})
				}
				for _, cr := range h.Creds {
					plain := decryptCredential(cr)
					if plain.PasswordError || plain.HashError {
						undecryptable++
					}
					eh.Credentials = append(eh.Credentials, exportCredential{
						Username: cr.Username, Password: plain.Password,
						Hash: plain.Hash, Source: cr.Source, CreatedAt: cr.CreatedAt,
					})
				}
				for _, n := range h.Notes {
					eh.Notes = append(eh.Notes, exportNote{
						Title: n.Title, Content: n.Content,
						SortOrder: n.SortOrder,
						CreatedAt: n.CreatedAt, UpdatedAt: n.UpdatedAt,
					})
				}
				for _, t := range h.ToolOutputs {
					eh.ToolOutputs = append(eh.ToolOutputs, exportToolOutput{
						Tool: t.Tool, Command: t.Command,
						Output: t.Output, CreatedAt: t.CreatedAt,
					})
				}
				for _, cmd := range hostCmdMap[h.ID] {
					eh.Commands = append(eh.Commands, exportCommand{
						OS: cmd.OS, Category: cmd.Category,
						Name: cmd.Name, Command: cmd.Command,
						Notes: cmd.Notes, CreatedAt: cmd.CreatedAt,
					})
				}
				ea.Hosts = append(ea.Hosts, eh)
			}
			bundle.Assessments = append(bundle.Assessments, ea)
		}

		// A bundle with blanked credentials would look like a good backup.
		if undecryptable > 0 {
			log.Printf("Export: refused, %d credential(s) cannot be decrypted with the current ENCRYPTION_KEY", undecryptable)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf(
				"export refused: %d stored credential(s) cannot be decrypted. The server's ENCRYPTION_KEY does not match the one they were saved with; restore it and export again.",
				undecryptable)})
			return
		}

		var commands []model.Command
		if err := db.Where("user_id = ? AND host_id IS NULL", userID).
			Order("created_at").Find(&commands).Error; err != nil {
			log.Printf("Export: load commands: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export data"})
			return
		}
		for _, cmd := range commands {
			bundle.Commands = append(bundle.Commands, exportCommand{
				OS: cmd.OS, Category: cmd.Category,
				Name: cmd.Name, Command: cmd.Command,
				Notes: cmd.Notes, CreatedAt: cmd.CreatedAt,
			})
		}

		// Import refuses the whole bundle over one invalid host identifier.
		if problems := bundle.validate(); len(problems) > 0 {
			log.Printf("Export: refused, host identifiers would be rejected on import")
			c.JSON(http.StatusConflict, gin.H{
				"error":    "export refused, it could not be imported again. Edit these hosts, then export again: " + strings.Join(problems, "; "),
				"rejected": problems,
			})
			return
		}

		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false) // tool output is full of <, > and &
		if err := enc.Encode(bundle); err != nil {
			log.Printf("Export: encode bundle: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to export data"})
			return
		}

		dateStr := time.Now().Format("2006-01-02")
		if c.Query("encrypt") == "true" {
			passphrase := c.GetHeader("X-Bundle-Passphrase")
			if len(passphrase) < 8 {
				c.JSON(http.StatusBadRequest, gin.H{"error": "encrypted export requires a passphrase of at least 8 characters (X-Bundle-Passphrase header)"})
				return
			}
			encrypted, err := encryptBundle(buf.Bytes(), passphrase)
			if err != nil {
				log.Printf("Export: encrypt bundle: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to encrypt export"})
				return
			}
			if !exportFits(c, len(encrypted)) {
				return
			}
			filename := fmt.Sprintf("penkeeper-export-%s.pne", dateStr)
			c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
			c.Data(http.StatusOK, "application/octet-stream", encrypted)
		} else {
			if !exportFits(c, buf.Len()) {
				return
			}
			filename := fmt.Sprintf("penkeeper-export-%s.json", dateStr)
			c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
			c.Data(http.StatusOK, "application/json; charset=utf-8", buf.Bytes())
		}
	}
}

// exportFits answers 413 and reports false when an export of size bytes
// could not be imported again.
func exportFits(c *gin.Context, size int) bool {
	if size <= importMaxBytes {
		return true
	}
	log.Printf("Export: refused, bundle is %d bytes (import limit %d)", size, importMaxBytes)
	c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf(
		"export refused: the bundle would be %.1f MB, over the %d MB import limit, so it could not be restored. Delete large tool outputs or notes, then export again.",
		float64(size)/(1<<20), importMaxBytes>>20)})
	return false
}

// ---------------------------------------------------------------------------
// Import – POST /api/v1/import
// ---------------------------------------------------------------------------

func Import(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		if refuseWhileKeyMismatch(c) {
			return
		}

		// Read one byte past the limit to tell a too-large bundle from one
		// that is exactly at it, instead of truncating it.
		fileBytes, err := io.ReadAll(io.LimitReader(c.Request.Body, importMaxBytes+1))
		if err != nil || len(fileBytes) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read upload"})
			return
		}
		if len(fileBytes) > importMaxBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": bundleTooLargeMsg})
			return
		}

		// Auto-detect and decrypt encrypted bundles (.pne files). They require
		// the passphrase supplied via the X-Bundle-Passphrase header.
		var envCheck encEnvelope
		if json.Unmarshal(fileBytes, &envCheck) == nil && envCheck.PNEEnc != 0 {
			fileBytes, err = decryptBundle(fileBytes, c.GetHeader("X-Bundle-Passphrase"))
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "failed to decrypt bundle: " + err.Error()})
				return
			}
		}

		var bundle exportBundle
		if err := json.Unmarshal(fileBytes, &bundle); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid export file: " + err.Error()})
			return
		}
		// Accept the current format and any older one we still understand.
		if bundle.Version < 1 || bundle.Version > exportVersion {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": fmt.Sprintf("unsupported export version %d (expected 1–%d)", bundle.Version, exportVersion),
			})
			return
		}
		skipped := bundle.skipped()
		repaired := bundle.repair()
		if problems := bundle.validate(); len(problems) > 0 {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":    "import rejected, nothing was imported: " + strings.Join(problems, "; "),
				"rejected": problems,
			})
			return
		}

		var assessmentsImported, hostsImported, commandsImported int

		if err := db.Transaction(func(tx *gorm.DB) error {
			for _, ea := range bundle.Assessments {
				if !ea.imported() {
					continue
				}
				a := model.Assessment{
					ID:         uuid.New(),
					OwnerID:    userID,
					Name:       ea.Name,
					ScratchPad: ea.ScratchPad,
					SortOrder:  ea.SortOrder,
					CreatedAt:  ea.CreatedAt,
					UpdatedAt:  ea.UpdatedAt,
				}
				if err := tx.Create(&a).Error; err != nil {
					return fmt.Errorf("create assessment %q: %w", ea.Name, err)
				}
				assessmentsImported++

				for _, eh := range ea.Hosts {
					h := model.Host{
						ID:           uuid.New(),
						AssessmentID: a.ID,
						Identifier:   eh.Identifier,
						Label:        eh.Label,
						DeviceType:   eh.DeviceType,
						OS:           eh.OS,
						Compromised:  eh.Compromised,
						CreatedAt:    eh.CreatedAt,
						UpdatedAt:    eh.UpdatedAt,
					}
					if err := tx.Create(&h).Error; err != nil {
						return fmt.Errorf("create host %q: %w", eh.Identifier, err)
					}
					hostsImported++

					for _, ep := range eh.Ports {
						serviceEdited, infoEdited := ep.editFlags()
						if err := tx.Create(&model.Port{
							ID: uuid.New(), HostID: h.ID,
							Number: ep.Number, Protocol: ep.Protocol,
							Service: ep.Service, Info: ep.Info,
							ScriptOutput:  ep.ScriptOutput,
							ServiceEdited: serviceEdited, InfoEdited: infoEdited,
							CreatedAt: ep.CreatedAt,
						}).Error; err != nil {
							return fmt.Errorf("create port: %w", err)
						}
					}

					for _, ec := range eh.Credentials {
						encPass, encHash, err := encryptCredentialSecrets(ec.Password, ec.Hash)
						if err != nil {
							return fmt.Errorf("encrypt credential: %w", err)
						}
						if err := tx.Create(&model.Credential{
							ID: uuid.New(), HostID: h.ID,
							Username: ec.Username, Password: encPass,
							Hash: encHash, Source: ec.Source, CreatedAt: ec.CreatedAt,
						}).Error; err != nil {
							return fmt.Errorf("create credential: %w", err)
						}
					}

					for _, en := range eh.Notes {
						if err := tx.Create(&model.Note{
							ID: uuid.New(), HostID: h.ID,
							Title: en.Title, Content: en.Content,
							SortOrder: en.SortOrder,
							CreatedAt: en.CreatedAt, UpdatedAt: en.UpdatedAt,
						}).Error; err != nil {
							return fmt.Errorf("create note: %w", err)
						}
					}

					for _, et := range eh.ToolOutputs {
						if err := tx.Create(&model.ToolOutput{
							ID: uuid.New(), HostID: h.ID,
							Tool: et.Tool, Command: et.Command,
							Output: et.Output, CreatedAt: et.CreatedAt,
						}).Error; err != nil {
							return fmt.Errorf("create tool output: %w", err)
						}
					}

					for _, ec := range eh.Commands {
						if err := tx.Create(&model.Command{
							ID: uuid.New(), UserID: userID, HostID: &h.ID,
							OS: ec.OS, Category: ec.Category,
							Name: ec.Name, Command: ec.Command,
							Notes: ec.Notes, CreatedAt: ec.CreatedAt,
						}).Error; err != nil {
							return fmt.Errorf("create host command: %w", err)
						}
						commandsImported++
					}
				}
			}

			for _, ec := range bundle.Commands {
				if err := tx.Create(&model.Command{
					ID: uuid.New(), UserID: userID,
					OS: ec.OS, Category: ec.Category,
					Name: ec.Name, Command: ec.Command,
					Notes: ec.Notes, CreatedAt: ec.CreatedAt,
				}).Error; err != nil {
					return fmt.Errorf("create command: %w", err)
				}
				commandsImported++
			}

			return nil
		}); err != nil {
			log.Printf("Import: transaction failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed: " + err.Error()})
			return
		}

		resp := gin.H{
			"assessments_imported": assessmentsImported,
			"hosts_imported":       hostsImported,
			"commands_imported":    commandsImported,
		}
		if len(repaired) > 0 {
			resp["repaired"] = repaired
		}
		if len(skipped) > 0 {
			resp["skipped"] = skipped
		}
		c.JSON(http.StatusOK, resp)
	}
}
