package api

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// -------------------------------------------------------------------
// Request payloads
// -------------------------------------------------------------------

// addCommandReq is used for global (library) commands.
type addCommandReq struct {
	OS       string `json:"os" binding:"required"`
	Category string `json:"category"`
	Name     string `json:"name" binding:"required"`
	Command  string `json:"command" binding:"required"`
	Notes    string `json:"notes"`
}

// addHostCommandReq is used for host-scoped commands.
type addHostCommandReq struct {
	Name    string `json:"name" binding:"required"`
	Command string `json:"command" binding:"required"`
	Notes   string `json:"notes"`
}

// commandWithHost is the response shape for ListCommands (includes optional host identifier).
type commandWithHost struct {
	model.Command
	HostIdentifier string `json:"host_identifier,omitempty" gorm:"column:host_identifier"`
}

// -------------------------------------------------------------------
// CreateCommand – POST /commands  (global/library command)
// -------------------------------------------------------------------
func CreateCommand(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		var req addCommandReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		cmd := model.Command{
			ID:       uuid.New(),
			UserID:   userID,
			OS:       req.OS,
			Category: req.Category,
			Name:     req.Name,
			Command:  req.Command,
			Notes:    req.Notes,
		}

		if err := db.Create(&cmd).Error; err != nil {
			log.Printf("CreateCommand DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store command"})
			return
		}

		c.JSON(http.StatusCreated, cmd)
	}
}

// -------------------------------------------------------------------
// ListCommands – GET /commands
// Returns all user commands (global + host-linked) with host identifier.
// Optional query param: ?os=Linux
// -------------------------------------------------------------------
func ListCommands(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		q := db.Model(&model.Command{}).
			Select("commands.*, COALESCE(hosts.identifier, '') as host_identifier").
			Joins("LEFT JOIN hosts ON commands.host_id = hosts.id").
			Where("commands.user_id = ?", userID)

		if osFilter := c.Query("os"); osFilter != "" {
			q = q.Where("commands.os = ?", osFilter)
		}

		var cmds []commandWithHost
		if err := q.Order("commands.created_at DESC").Find(&cmds).Error; err != nil {
			log.Printf("ListCommands DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch commands"})
			return
		}
		c.JSON(http.StatusOK, cmds)
	}
}

// -------------------------------------------------------------------
// GetCommand – GET /commands/:cid
// -------------------------------------------------------------------
func GetCommand(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		cmdID, err := uuid.Parse(c.Param("cid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid command id"})
			return
		}

		cmd := verifyCommandOwner(db, cmdID, userID)
		if cmd == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
			return
		}

		c.JSON(http.StatusOK, cmd)
	}
}

// -------------------------------------------------------------------
// UpdateCommand – PUT /commands/:cid  (global/library command)
// -------------------------------------------------------------------
func UpdateCommand(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		cmdID, err := uuid.Parse(c.Param("cid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid command id"})
			return
		}

		if verifyCommandOwner(db, cmdID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
			return
		}

		var payload struct {
			OS       string `json:"os"`
			Category string `json:"category"`
			Name     string `json:"name"`
			Command  string `json:"command"`
			Notes    string `json:"notes"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if payload.OS == "" || payload.Name == "" || payload.Command == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "os, name, and command are required"})
			return
		}

		result := db.Model(&model.Command{}).
			Where("id = ? AND user_id = ?", cmdID, userID).
			Updates(map[string]interface{}{
				"os":       payload.OS,
				"category": payload.Category,
				"name":     payload.Name,
				"command":  payload.Command,
				"notes":    payload.Notes,
			})

		if result.Error != nil {
			log.Printf("UpdateCommand DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update command"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}

// -------------------------------------------------------------------
// DeleteCommand – DELETE /commands/:cid
// -------------------------------------------------------------------
func DeleteCommand(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		cmdID, err := uuid.Parse(c.Param("cid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid command id"})
			return
		}

		if verifyCommandOwner(db, cmdID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
			return
		}

		result := db.Where("id = ? AND user_id = ?", cmdID, userID).Delete(&model.Command{})
		if result.Error != nil {
			log.Printf("DeleteCommand DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete command"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}

// -------------------------------------------------------------------
// ListHostCommands – GET /hosts/:hid/commands
// -------------------------------------------------------------------
func ListHostCommands(db *storage.DB) gin.HandlerFunc {
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

		var cmds []model.Command
		if err := db.Where("host_id = ?", hid).Order("created_at DESC").Find(&cmds).Error; err != nil {
			log.Printf("ListHostCommands DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch commands"})
			return
		}
		c.JSON(http.StatusOK, cmds)
	}
}

// -------------------------------------------------------------------
// CreateHostCommand – POST /hosts/:hid/commands
// -------------------------------------------------------------------
func CreateHostCommand(db *storage.DB) gin.HandlerFunc {
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

		var req addHostCommandReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		cmd := model.Command{
			ID:      uuid.New(),
			UserID:  userID,
			HostID:  &hid,
			Name:    req.Name,
			Command: req.Command,
			Notes:   req.Notes,
		}

		if err := db.Create(&cmd).Error; err != nil {
			log.Printf("CreateHostCommand DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store command"})
			return
		}

		c.JSON(http.StatusCreated, cmd)
	}
}

// -------------------------------------------------------------------
// UpdateHostCommand – PUT /hosts/:hid/commands/:cid
// -------------------------------------------------------------------
func UpdateHostCommand(db *storage.DB) gin.HandlerFunc {
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

		cmdID, err := uuid.Parse(c.Param("cid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid command id"})
			return
		}

		var payload struct {
			Name    string `json:"name"`
			Command string `json:"command"`
			Notes   string `json:"notes"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if payload.Name == "" || payload.Command == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name and command are required"})
			return
		}

		result := db.Model(&model.Command{}).
			Where("id = ? AND host_id = ?", cmdID, hid).
			Updates(map[string]interface{}{
				"name":    payload.Name,
				"command": payload.Command,
				"notes":   payload.Notes,
			})

		if result.Error != nil {
			log.Printf("UpdateHostCommand DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update command"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}

// -------------------------------------------------------------------
// DeleteHostCommand – DELETE /hosts/:hid/commands/:cid
// -------------------------------------------------------------------
func DeleteHostCommand(db *storage.DB) gin.HandlerFunc {
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

		cmdID, err := uuid.Parse(c.Param("cid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid command id"})
			return
		}

		result := db.Where("id = ? AND host_id = ?", cmdID, hid).Delete(&model.Command{})
		if result.Error != nil {
			log.Printf("DeleteHostCommand DB error: %v", result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete command"})
			return
		}
		if result.RowsAffected == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "command not found"})
			return
		}

		c.Status(http.StatusNoContent)
	}
}
