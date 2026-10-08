package api

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// errNoSibling signals that a note is already at the top/bottom and there is no
// adjacent note to swap with — treated as a no-op, not an error.
var errNoSibling = errors.New("no adjacent note")

// ownedHost is verifyHostOwner for the note editor's save and read paths:
// (false, nil) when the host doesn't exist or isn't the user's, and the
// error when a lookup failed (see ownedAssessment).
func ownedHost(db *storage.DB, hostID, userID uuid.UUID) (bool, error) {
	var host model.Host
	found, err := rowFound(db.Select("id", "assessment_id").First(&host, "id = ?", hostID).Error)
	if !found {
		return false, err
	}
	return ownedAssessment(db, host.AssessmentID, userID)
}

// -------------------------------------------------------------------
// CreateNote – POST /hosts/:hid/notes
// -------------------------------------------------------------------
func CreateNote(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		if verifyHostOwner(db, hid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var payload struct {
			Title   string `json:"title"`
			Content string `json:"content"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request payload"})
			return
		}

		if payload.Title == "" {
			payload.Title = "Untitled"
		}

		// Set sort_order to max existing + 1 so new notes appear at the bottom
		var maxOrder int
		db.Model(&model.Note{}).Where("host_id = ?", hid).
			Select("COALESCE(MAX(sort_order), 0)").Scan(&maxOrder)

		note := model.Note{
			ID:        uuid.New(),
			HostID:    hid,
			Title:     payload.Title,
			Content:   payload.Content,
			SortOrder: maxOrder + 1,
		}
		if err := db.Create(&note).Error; err != nil {
			log.Printf("CreateNote DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create note"})
			return
		}
		c.JSON(http.StatusCreated, note)
	}
}

// -------------------------------------------------------------------
// ListNotes – GET /hosts/:hid/notes
// -------------------------------------------------------------------
func ListNotes(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		if verifyHostOwner(db, hid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var notes []model.Note
		if err := db.Where("host_id = ?", hid).Order("sort_order ASC, created_at ASC").Find(&notes).Error; err != nil {
			log.Printf("ListNotes DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch notes"})
			return
		}
		c.JSON(http.StatusOK, notes)
	}
}

// -------------------------------------------------------------------
// GetNote – GET /notes/:nid
// -------------------------------------------------------------------
func GetNote(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		nid, err := uuid.Parse(c.Param("nid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid note id"})
			return
		}

		// Only a missing (or foreign) note is a 404; a failed lookup is a
		// 500 (see ownedAssessment).
		var note model.Note
		found, err := rowFound(db.First(&note, "id = ?", nid).Error)
		if found {
			found, err = ownedHost(db, note.HostID, userID)
		}
		if err != nil {
			log.Printf("GetNote DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch note"})
			return
		}
		if !found {
			c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
			return
		}
		c.JSON(http.StatusOK, note)
	}
}

// updateNoteReq is the body of PUT /hosts/:hid/notes/:nid. Every field is
// optional and only the fields present are written, so a rename can send the
// title alone. Version is the note version the client loaded: when it is
// present the update only applies if the note is still at that version.
// Without it the update overwrites unconditionally (older clients).
//
// SaveID is an optional client-chosen id for this save, stored with the
// note. BaseSaveIDs lists (up to 16) earlier saves of the same client whose
// replies were lost, so it can't tell whether they were applied: with
// Version, the update also applies when the note is still as one of those
// saves left it. A client can therefore retry after a lost reply (or save
// once more while a save is still in flight, as the page closes) without a
// false conflict with its own write, and still never overwrites anyone
// else's.
type updateNoteReq struct {
	Title       *string  `json:"title"`
	Content     *string  `json:"content"`
	Version     *int     `json:"version"`
	SaveID      string   `json:"save_id" binding:"max=64"`
	BaseSaveIDs []string `json:"base_save_ids" binding:"max=16,dive,min=1,max=64"`
}

// columns returns the column updates for the request: the provided fields
// plus a version bump and the save id. It returns nil when the request
// changes nothing.
func (r updateNoteReq) columns() map[string]interface{} {
	cols := map[string]interface{}{}
	if r.Title != nil {
		cols["title"] = *r.Title
	}
	if r.Content != nil {
		cols["content"] = *r.Content
	}
	if len(cols) == 0 {
		return nil
	}
	cols["version"] = gorm.Expr("version + 1")
	// Always written, so an id left by an earlier save never matches once
	// someone else (or an older client, sending none) has written.
	cols["save_id"] = r.SaveID
	return cols
}

// saveGuard holds the WHERE clauses that keep a versioned save from
// overwriting newer text: the row must still be at the version the client
// edited, or as one of the client's own unconfirmed saves left it.
type saveGuard struct {
	byVersion       string // version only
	byVersionOrSave string // version, or one of the listed save ids
}

var (
	noteSaveGuard       = saveGuard{"version = ?", "(version = ? OR save_id IN ?)"}
	scratchPadSaveGuard = saveGuard{"scratch_pad_version = ?", "(scratch_pad_version = ? OR scratch_pad_save_id IN ?)"}
)

// where returns the guard for a save based on version (nil: older client,
// unconditional save, ok is false) and the client's unconfirmed saves.
func (g saveGuard) where(version *int, baseSaveIDs []string) (query string, args []interface{}, ok bool) {
	if version == nil {
		return "", nil, false
	}
	if len(baseSaveIDs) == 0 {
		return g.byVersion, []interface{}{*version}, true
	}
	return g.byVersionOrSave, []interface{}{*version, baseSaveIDs}, true
}

// noteConflictBody is the 409 response for an update based on an old
// version: it carries the current copy so the client can offer to load it
// or to save its own text over it. save_id tells a client whether the
// current copy is one of its own saves.
func noteConflictBody(n model.Note) gin.H {
	return gin.H{
		"error": "note changed elsewhere",
		"note": gin.H{
			"id":         n.ID,
			"title":      n.Title,
			"content":    n.Content,
			"version":    n.Version,
			"save_id":    n.SaveID,
			"updated_at": n.UpdatedAt,
		},
	}
}

// -------------------------------------------------------------------
// UpdateNote – PUT /hosts/:hid/notes/:nid
// Body: { title?, content?, version?, save_id?, base_save_ids? } →
// 200 { version }, or 409 with the current note when version is given and
// the note has changed since (other than by the saves in base_save_ids).
// -------------------------------------------------------------------
func UpdateNote(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		nid, err := uuid.Parse(c.Param("nid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid note id"})
			return
		}

		owned, err := ownedHost(db, hid, userID)
		if err != nil {
			log.Printf("UpdateNote DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update note"})
			return
		}
		if !owned {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var payload updateNoteReq
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		cols := payload.columns()
		if cols == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "title or content required"})
			return
		}

		q := db.Where("id = ? AND host_id = ?", nid, hid)
		if guard, args, ok := noteSaveGuard.where(payload.Version, payload.BaseSaveIDs); ok {
			q = q.Where(guard, args...)
		}
		// RETURNING hands back the bumped version from the same statement.
		var updated model.Note
		result := q.Model(&updated).
			Clauses(clause.Returning{Columns: []clause.Column{{Name: "version"}}}).
			Updates(cols)

		if result.Error != nil {
			log.Printf("UpdateNote DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update note"})
			return
		}
		if result.RowsAffected == 0 {
			if payload.Version == nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
				return
			}
			// No row matched: either the note isn't on this host, or it has
			// moved past the version the client based its edit on.
			var current model.Note
			if err := db.First(&current, "id = ? AND host_id = ?", nid, hid).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
					return
				}
				log.Printf("UpdateNote DB error: %v", err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update note"})
				return
			}
			c.JSON(http.StatusConflict, noteConflictBody(current))
			return
		}
		c.JSON(http.StatusOK, gin.H{"version": updated.Version})
	}
}

// -------------------------------------------------------------------
// DeleteNote – DELETE /hosts/:hid/notes/:nid
// -------------------------------------------------------------------
func DeleteNote(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		nid, err := uuid.Parse(c.Param("nid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid note id"})
			return
		}

		if verifyHostOwner(db, hid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		result := db.Where("id = ? AND host_id = ?", nid, hid).Delete(&model.Note{})
		if result.Error != nil {
			log.Printf("DeleteNote DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete note"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// -------------------------------------------------------------------
// MoveNote – PUT /hosts/:hid/notes/:nid/move
// Swaps sort_order with the adjacent note above or below.
// -------------------------------------------------------------------
func MoveNote(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hid, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		nid, err := uuid.Parse(c.Param("nid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid note id"})
			return
		}

		if verifyHostOwner(db, hid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var payload struct {
			Direction string `json:"direction"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil ||
			(payload.Direction != "up" && payload.Direction != "down") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "direction must be 'up' or 'down'"})
			return
		}

		// Read both rows and swap their sort_order inside one transaction,
		// locking the rows FOR UPDATE so concurrent moves can't interleave and
		// produce duplicate/inconsistent ordering.
		txErr := db.Transaction(func(tx *gorm.DB) error {
			var note model.Note
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
				First(&note, "id = ? AND host_id = ?", nid, hid).Error; err != nil {
				return err // ErrRecordNotFound → 404 below
			}

			var sibling model.Note
			q := tx.Clauses(clause.Locking{Strength: "UPDATE"})
			if payload.Direction == "up" {
				q = q.Where("host_id = ? AND sort_order < ?", hid, note.SortOrder).Order("sort_order DESC")
			} else {
				q = q.Where("host_id = ? AND sort_order > ?", hid, note.SortOrder).Order("sort_order ASC")
			}
			if err := q.First(&sibling).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return errNoSibling // already at top/bottom — no-op
				}
				return err
			}

			if err := tx.Model(&model.Note{}).Where("id = ?", note.ID).
				Update("sort_order", sibling.SortOrder).Error; err != nil {
				return err
			}
			return tx.Model(&model.Note{}).Where("id = ?", sibling.ID).
				Update("sort_order", note.SortOrder).Error
		})

		switch {
		case txErr == nil, errors.Is(txErr, errNoSibling):
			c.Status(http.StatusNoContent)
		case errors.Is(txErr, gorm.ErrRecordNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
		default:
			log.Printf("MoveNote DB error: %v", txErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to move note"})
		}
	}
}

// -------------------------------------------------------------------
// UpdateNoteOrder – PUT /hosts/:hid/notes/:nid/order
// Sets a note's sort_order directly. Drag-and-drop reordering calls this for
// each note in the new order (sort_order = position), mirroring assessments.
// -------------------------------------------------------------------
func UpdateNoteOrder(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		nid, err := uuid.Parse(c.Param("nid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid note id"})
			return
		}

		if verifyNoteOwner(db, nid, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "note not found"})
			return
		}

		var payload struct {
			SortOrder int `json:"sort_order"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := db.Model(&model.Note{}).Where("id = ?", nid).
			Update("sort_order", payload.SortOrder).Error; err != nil {
			log.Printf("UpdateNoteOrder DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update note order"})
			return
		}
		c.Status(http.StatusNoContent)
	}
}
