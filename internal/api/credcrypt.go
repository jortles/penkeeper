package api

import (
	"log"
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"

	appcrypto "penkeeper/internal/crypto"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// credentialView is a credential as the API returns it: Password and Hash
// decrypted. PasswordError and HashError mark a stored value that could not
// be decrypted (wrong ENCRYPTION_KEY); that value is then sent as "" (never
// the ciphertext), and the stored one is left as it is.
type credentialView struct {
	model.Credential
	PasswordError bool `json:"password_error,omitempty"`
	HashError     bool `json:"hash_error,omitempty"`
}

// decryptCredential returns cr with its Password and Hash decrypted. Values
// written before encryption at rest (plaintext) pass through unchanged.
func decryptCredential(cr model.Credential) credentialView {
	v := credentialView{Credential: cr}
	var err error
	if v.Password, err = appcrypto.Decrypt(cr.Password); err != nil {
		v.Password, v.PasswordError = "", true
	}
	if v.Hash, err = appcrypto.Decrypt(cr.Hash); err != nil {
		v.Hash, v.HashError = "", true
	}
	return v
}

// encryptCredentialSecrets encrypts a credential's password and hash for
// storage.
func encryptCredentialSecrets(password, hash string) (encPass, encHash string, err error) {
	if encPass, err = appcrypto.Encrypt(password); err != nil {
		return "", "", err
	}
	if encHash, err = appcrypto.Encrypt(hash); err != nil {
		return "", "", err
	}
	return encPass, encHash, nil
}

// PrepareCredentialStore runs at start-up, after the database is open. It
// trial-decrypts one stored encrypted value and logs a warning when the
// at-rest key cannot read it. With a working key it then encrypts credential
// passwords and hashes and TOTP secrets still stored in plaintext (written by
// older versions); values already encrypted are skipped, so running it on
// every start is safe.
func PrepareCredentialStore(db *storage.DB) {
	if !atRestKeyWorks(db) {
		keyMismatch.Store(true)
		log.Printf("Skipping encryption of plaintext credentials, and refusing to save credentials or import, until the key is fixed.")
		return
	}
	n, err := encryptPlaintextCredentials(db.DB)
	if err != nil {
		log.Printf("WARNING: encrypting plaintext credentials failed (nothing changed): %v", err)
		return
	}
	if n > 0 {
		log.Printf("Encrypted the plaintext password or hash of %d stored credential(s).", n)
	}
	n, err = encryptPlaintextTOTPSecrets(db.DB)
	if err != nil {
		log.Printf("WARNING: encrypting plaintext TOTP secrets failed (nothing changed): %v", err)
		return
	}
	if n > 0 {
		log.Printf("Encrypted the plaintext TOTP secret of %d user(s).", n)
	}
}

// keyMismatch is set at start-up when the at-rest key cannot decrypt the
// stored data. Credentials are then not written: anything saved would be
// encrypted with the wrong key and become unreadable once the key is fixed.
var keyMismatch atomic.Bool

// refuseWhileKeyMismatch answers 503 and returns true while keyMismatch is
// set.
func refuseWhileKeyMismatch(c *gin.Context) bool {
	if !keyMismatch.Load() {
		return false
	}
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": "the server's ENCRYPTION_KEY does not match the stored data, so credentials cannot be saved until it is fixed"})
	return true
}

// atRestKeyWorks reports whether the current key decrypts stored data (true
// when there is none to try). It samples the columns older versions already
// encrypted (passwords and TOTP secrets), and hashes only when those hold
// nothing encrypted: a hash written by an older version is plaintext, even
// one that happens to start with "enc:". The key works if any sample
// decrypts.
func atRestKeyWorks(db *storage.DB) bool {
	var sample []string
	err := db.Raw(`SELECT v FROM (
		(SELECT password AS v FROM credentials WHERE password LIKE 'enc:%' LIMIT 5)
		UNION ALL (SELECT totp_secret FROM users WHERE totp_secret LIKE 'enc:%' LIMIT 5)
	) s`).Scan(&sample).Error
	if err == nil && len(sample) == 0 {
		err = db.Raw(`SELECT hash FROM credentials WHERE hash LIKE 'enc:%' LIMIT 5`).Scan(&sample).Error
	}
	if err != nil {
		log.Printf("WARNING: could not check the at-rest encryption key: %v", err)
		return false
	}
	if len(sample) == 0 {
		log.Printf("No encrypted data yet; the at-rest key was not checked.")
		return true
	}
	for _, v := range sample {
		if _, err = appcrypto.Decrypt(v); err == nil {
			log.Printf("At-rest encryption key verified against stored data.")
			return true
		}
	}
	log.Printf(`
================================================================================
  WARNING: ENCRYPTION_KEY DOES NOT MATCH THE STORED DATA
================================================================================

  A stored encrypted value cannot be decrypted with the current key (%v).
  Credential passwords and hashes will show as "cannot be decrypted", exports
  are refused, and users with 2FA cannot sign in.

  Restore the ENCRYPTION_KEY (or, if it was never set, the JWT_SECRET) that
  the data was written with, then restart. Nothing has been changed.

================================================================================`, err)
	return false
}

// encryptPlaintextCredentials encrypts every non-empty credential password
// and hash that is not yet encrypted, in one transaction, and returns how
// many credentials it changed.
func encryptPlaintextCredentials(db *gorm.DB) (int, error) {
	changed := 0
	err := db.Transaction(func(tx *gorm.DB) error {
		var rows []struct {
			ID       uuid.UUID
			Password string
			Hash     string
		}
		// Hashes are read even when they look encrypted: older versions never
		// encrypted hashes, so one that does not decrypt with the verified key
		// is plaintext that happens to start with "enc:".
		if err := tx.Raw(`SELECT id, COALESCE(password, '') AS password, COALESCE(hash, '') AS hash
			FROM credentials
			WHERE (password <> '' AND password NOT LIKE 'enc:%') OR hash <> ''
			FOR UPDATE`).Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			cols := map[string]interface{}{}
			for col, val := range map[string]string{"password": r.Password, "hash": r.Hash} {
				if val == "" {
					continue
				}
				if appcrypto.IsEncrypted(val) {
					if col == "password" {
						continue
					}
					if _, err := appcrypto.Decrypt(val); err == nil {
						continue
					}
				}
				enc, err := appcrypto.Encrypt(val)
				if err != nil {
					return err
				}
				cols[col] = enc
			}
			if len(cols) == 0 {
				continue
			}
			if err := tx.Table("credentials").Where("id = ?", r.ID).Updates(cols).Error; err != nil {
				return err
			}
			changed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
}

// encryptPlaintextTOTPSecrets encrypts every TOTP secret that is not yet
// encrypted, in one transaction, and returns how many users it changed.
func encryptPlaintextTOTPSecrets(db *gorm.DB) (int, error) {
	changed := 0
	err := db.Transaction(func(tx *gorm.DB) error {
		var rows []struct {
			ID     uuid.UUID
			Secret string
		}
		if err := tx.Raw(`SELECT id, totp_secret AS secret FROM users
			WHERE totp_secret <> '' AND totp_secret NOT LIKE 'enc:%'
			FOR UPDATE`).Scan(&rows).Error; err != nil {
			return err
		}
		for _, r := range rows {
			enc, err := appcrypto.Encrypt(r.Secret)
			if err != nil {
				return err
			}
			if err := tx.Table("users").Where("id = ?", r.ID).Update("totp_secret", enc).Error; err != nil {
				return err
			}
			changed++
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
}
