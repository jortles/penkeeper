package api

import (
	"time"

	"github.com/google/uuid"

	"penkeeper/internal/model"
)

// assessmentSummary is one row of GET /assessments: what the dashboard
// shows, without credentials, notes or tool output.
type assessmentSummary struct {
	ID        uuid.UUID `json:"id"`
	OwnerID   uuid.UUID `json:"owner_id"`
	Name      string    `json:"name"`
	SortOrder int       `json:"sort_order"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	HostCount int       `json:"host_count"`
	PortCount int       `json:"port_count"`
	// Hosts holds each host's id and one empty entry per port, so clients
	// written for the old full listing (hosts[].ports.length) still count
	// right.
	Hosts []hostStub `json:"hosts"`
}

type hostStub struct {
	ID    uuid.UUID  `json:"id"`
	Ports []struct{} `json:"ports"`
}

// hostPortCount is a host of the listed assessments with its port count.
type hostPortCount struct {
	ID           uuid.UUID
	AssessmentID uuid.UUID
	Ports        int
}

// assessmentSummaries builds the listing from the assessments (in display
// order) and their hosts.
func assessmentSummaries(engs []model.Assessment, hosts []hostPortCount) []assessmentSummary {
	out := make([]assessmentSummary, len(engs))
	idx := make(map[uuid.UUID]int, len(engs))
	for i, e := range engs {
		idx[e.ID] = i
		out[i] = assessmentSummary{
			ID: e.ID, OwnerID: e.OwnerID, Name: e.Name,
			SortOrder: e.SortOrder, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt,
			Hosts: []hostStub{},
		}
	}
	for _, h := range hosts {
		i, ok := idx[h.AssessmentID]
		if !ok {
			continue
		}
		s := &out[i]
		s.HostCount++
		s.PortCount += h.Ports
		s.Hosts = append(s.Hosts, hostStub{ID: h.ID, Ports: make([]struct{}, h.Ports)})
	}
	return out
}
