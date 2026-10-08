package api

import (
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/google/uuid"
	"gorm.io/gorm/clause"

	"penkeeper/internal/model"
)

// TestUpdateNoteReqColumns checks that only the fields present in the body
// are written (so a rename can't touch the content), that every write bumps
// the version and records the save id, and that version 0 still counts as
// "given" (rows that existed before versioning start at 0).
func TestUpdateNoteReqColumns(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantCols    []string // columns written besides version; nil = nothing to update
		wantVersion *int
	}{
		{"title and content", `{"title":"T","content":"<p>C</p>","version":3}`, []string{"title", "content"}, intPtr(3)},
		{"title only (rename)", `{"title":"Renamed","version":5}`, []string{"title"}, intPtr(5)},
		{"content only", `{"content":"<p>C</p>"}`, []string{"content"}, nil},
		{"empty content is still an update", `{"content":""}`, []string{"content"}, nil},
		{"null title is omitted", `{"title":null,"content":"x"}`, []string{"content"}, nil},
		{"version zero is a real version", `{"title":"T","version":0}`, []string{"title"}, intPtr(0)},
		{"old client without version", `{"title":"T","content":"C"}`, []string{"title", "content"}, nil},
		{"nothing to update", `{"version":2}`, nil, intPtr(2)},
		{"empty object", `{}`, nil, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req updateNoteReq
			if err := binding.JSON.BindBody([]byte(tc.body), &req); err != nil {
				t.Fatalf("bind %s: %v", tc.body, err)
			}
			if (req.Version == nil) != (tc.wantVersion == nil) ||
				(req.Version != nil && *req.Version != *tc.wantVersion) {
				t.Errorf("Version = %v, want %v", deref(req.Version), deref(tc.wantVersion))
			}

			cols := req.columns()
			if tc.wantCols == nil {
				if cols != nil {
					t.Fatalf("columns() = %v, want nil", cols)
				}
				return
			}
			if len(cols) != len(tc.wantCols)+2 {
				t.Errorf("columns() = %v, want %v plus version and save_id", cols, tc.wantCols)
			}
			if id, ok := cols["save_id"]; !ok || id != "" {
				t.Errorf("save_id column = %#v, want \"\" (none sent)", id)
			}
			for _, k := range tc.wantCols {
				if _, ok := cols[k]; !ok {
					t.Errorf("columns() missing %q: %v", k, cols)
				}
			}
			expr, ok := cols["version"].(clause.Expr)
			if !ok || expr.SQL != "version + 1" {
				t.Errorf("version column = %#v, want version + 1", cols["version"])
			}
		})
	}
}

// TestUpdateNoteReqValues makes sure the written values are the ones sent,
// including an explicitly empty content.
func TestUpdateNoteReqValues(t *testing.T) {
	var req updateNoteReq
	if err := binding.JSON.BindBody([]byte(`{"title":"Recon","content":""}`), &req); err != nil {
		t.Fatal(err)
	}
	cols := req.columns()
	if cols["title"] != "Recon" || cols["content"] != "" {
		t.Errorf("columns() = %v", cols)
	}
}

// TestUpdateNoteReqSaveIDs checks the save id fields: the id is stored with
// the write, and base_save_ids is bounded (at most 16 ids of 1-64 chars), so
// an empty id can never match the column default.
func TestUpdateNoteReqSaveIDs(t *testing.T) {
	var req updateNoteReq
	body := `{"content":"<p>x</p>","version":3,"save_id":"0f1e2d3c","base_save_ids":["aa","bb"]}`
	if err := binding.JSON.BindBody([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if cols := req.columns(); cols["save_id"] != "0f1e2d3c" {
		t.Errorf("save_id column = %v", cols["save_id"])
	}
	if len(req.BaseSaveIDs) != 2 || req.BaseSaveIDs[0] != "aa" || req.BaseSaveIDs[1] != "bb" {
		t.Errorf("BaseSaveIDs = %v", req.BaseSaveIDs)
	}

	ids := func(n int, id string) string {
		out := make([]string, n)
		for i := range out {
			out[i] = `"` + id + `"`
		}
		return "[" + strings.Join(out, ",") + "]"
	}
	long := strings.Repeat("a", 65)
	cases := []struct {
		body string
		ok   bool
	}{
		{`{"content":"x","version":1,"base_save_ids":` + ids(16, "a") + `}`, true},
		{`{"content":"x","version":1,"base_save_ids":` + ids(17, "a") + `}`, false},
		{`{"content":"x","version":1,"base_save_ids":[""]}`, false},
		{`{"content":"x","version":1,"base_save_ids":["` + long + `"]}`, false},
		{`{"content":"x","save_id":"` + long + `"}`, false},
		{`{"content":"x","save_id":"` + long[:64] + `"}`, true},
	}
	for _, tc := range cases {
		var r updateNoteReq
		err := binding.JSON.BindBody([]byte(tc.body), &r)
		if (err == nil) != tc.ok {
			t.Errorf("bind %.60s...: err = %v, want ok = %v", tc.body, err, tc.ok)
		}
	}
}

// TestNoteSaveGuard pins the WHERE clause of a versioned note save: the
// version alone, or the version or one of the client's unconfirmed saves.
func TestNoteSaveGuard(t *testing.T) {
	if _, _, ok := noteSaveGuard.where(nil, nil); ok {
		t.Error("no version: want an unconditional save")
	}
	q, args, ok := noteSaveGuard.where(intPtr(0), []string{})
	if !ok || q != "version = ?" || len(args) != 1 || args[0] != 0 {
		t.Errorf("where(0) = %q %v %v", q, args, ok)
	}
	q, args, ok = noteSaveGuard.where(intPtr(7), []string{"x1"})
	if !ok || q != "(version = ? OR save_id IN ?)" || len(args) != 2 || args[0] != 7 {
		t.Errorf("where(7, ids) = %q %v %v", q, args, ok)
	}
	if ids, _ := args[1].([]string); len(ids) != 1 || ids[0] != "x1" {
		t.Errorf("ids arg = %#v", args[1])
	}
}

func TestUpdateNoteReqRejectsBadVersion(t *testing.T) {
	for _, body := range []string{`{"title":"T","version":"3"}`, `{"title":"T","version":1.5}`} {
		var req updateNoteReq
		if err := binding.JSON.BindBody([]byte(body), &req); err == nil {
			t.Errorf("bind %s: want error, got %+v", body, req)
		}
	}
}

// TestNoteConflictBody pins the 409 shape the editor reads to offer
// "Load latest" / "Keep mine".
func TestNoteConflictBody(t *testing.T) {
	n := model.Note{
		ID:        uuid.New(),
		HostID:    uuid.New(),
		Title:     "Recon",
		Content:   "<p>newer text</p>",
		Version:   7,
		SaveID:    "s7",
		UpdatedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
	}
	body := noteConflictBody(n)
	if body["error"] != "note changed elsewhere" {
		t.Errorf("error = %v", body["error"])
	}
	note, ok := body["note"].(gin.H)
	if !ok {
		t.Fatalf("note = %#v", body["note"])
	}
	want := gin.H{"id": n.ID, "title": "Recon", "content": "<p>newer text</p>", "version": 7, "save_id": "s7", "updated_at": n.UpdatedAt}
	for k, v := range want {
		if note[k] != v {
			t.Errorf("note[%q] = %v, want %v", k, note[k], v)
		}
	}
	if len(note) != len(want) {
		t.Errorf("note has extra fields: %v", note)
	}
}

func intPtr(v int) *int { return &v }

func deref(p *int) interface{} {
	if p == nil {
		return nil
	}
	return *p
}
