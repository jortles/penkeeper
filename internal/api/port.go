package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"penkeeper/internal/model"
	"penkeeper/internal/storage"
)

// -------------------------------------------------------------------
// Request payload
// -------------------------------------------------------------------
type addPortReq struct {
	// A pointer, so 0 (valid for protocol ip) is told apart from a missing number.
	Number   *uint16 `json:"number" binding:"required"`
	Protocol string  `json:"protocol" binding:"required,oneof=tcp udp sctp ip"`
	Service  string  `json:"service"`
	Info     string  `json:"info"`
}

// validPortProtocol reports whether p is a protocol the app accepts — the set
// nmap can emit in its XML (tcp, udp, sctp, ip). Shared by AddPort/UpdatePort.
func validPortProtocol(p string) bool {
	switch p {
	case "tcp", "udp", "sctp", "ip":
		return true
	default:
		return false
	}
}

// validPortNumber reports whether number is in range for protocol: an IP
// protocol number (nmap -sO, protocol "ip") is 0-255, a tcp/udp/sctp port
// 1-65535. Shared by AddPort, UpdatePort and the Nmap import.
func validPortNumber(number int, protocol string) bool {
	if protocol == "ip" {
		return number >= 0 && number <= 255
	}
	return number >= 1 && number <= 65535
}

var errPortNumber = errors.New("port number out of range (1-65535, or 0-255 for protocol ip)")

// hasValue reports whether a Service or Info value says anything. Only such
// a value can be marked as typed by the user; an empty field is always left
// for Nmap imports to fill.
func hasValue(s string) bool { return strings.TrimSpace(s) != "" }

// newManualPort builds the port AddPort stores. A Service or Info typed in
// is marked as the user's (ServiceEdited/InfoEdited), so a later Nmap import
// keeps it instead of the scanned value.
func newManualPort(hostID uuid.UUID, req addPortReq) (model.Port, error) {
	if !validPortProtocol(req.Protocol) {
		return model.Port{}, errors.New("protocol must be tcp, udp, sctp, or ip")
	}
	if req.Number == nil || !validPortNumber(int(*req.Number), req.Protocol) {
		return model.Port{}, errPortNumber
	}
	return model.Port{
		ID:            uuid.New(),
		HostID:        hostID,
		Number:        *req.Number,
		Protocol:      req.Protocol,
		Service:       req.Service,
		Info:          req.Info,
		ServiceEdited: hasValue(req.Service),
		InfoEdited:    hasValue(req.Info),
	}, nil
}

// -------------------------------------------------------------------
// AddPort – POST /hosts/:hid/ports
// -------------------------------------------------------------------
func AddPort(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hostID, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		portHost := verifyHostOwner(db, hostID, userID)
		if portHost == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var req addPortReq
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		p, err := newManualPort(hostID, req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if err := db.Create(&p).Error; err != nil {
			log.Printf("AddPort DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store port"})
			return
		}
		go RecordActivity(db, portHost.AssessmentID, userID, "port_added",
			fmt.Sprintf("Added port %d/%s on %s", p.Number, p.Protocol, portHost.Identifier))
		c.JSON(http.StatusCreated, p)
	}
}

// -------------------------------------------------------------------
// ListPorts – GET /hosts/:hid/ports
// -------------------------------------------------------------------
func ListPorts(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		hostID, err := uuid.Parse(c.Param("hid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid host id"})
			return
		}

		if verifyHostOwner(db, hostID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
			return
		}

		var ports []model.Port
		if err := db.Where("host_id = ?", hostID).Find(&ports).Error; err != nil {
			log.Printf("ListPorts DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch ports"})
			return
		}
		c.JSON(http.StatusOK, ports)
	}
}

// -------------------------------------------------------------------
// GetPort – GET /ports/:pid
// -------------------------------------------------------------------
func GetPort(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		portID, err := uuid.Parse(c.Param("pid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid port id"})
			return
		}

		port := verifyPortOwner(db, portID, userID)
		if port == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "port not found"})
			return
		}

		c.JSON(http.StatusOK, port)
	}
}

// -------------------------------------------------------------------
// ListAssessmentPorts – GET /assessments/:eid/ports
// -------------------------------------------------------------------
func ListAssessmentPorts(db *storage.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := getUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		engID, err := uuid.Parse(c.Param("eid"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assessment id"})
			return
		}

		if verifyAssessmentOwner(db, engID, userID) == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "assessment not found"})
			return
		}

		var ports []model.Port
		if err := db.Joins("JOIN hosts ON hosts.id = ports.host_id").
			Where("hosts.assessment_id = ?", engID).
			Find(&ports).Error; err != nil {
			log.Printf("ListAssessmentPorts DB error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch ports"})
			return
		}
		c.JSON(http.StatusOK, ports)
	}
}
