package api

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gin-gonic/gin/binding"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"penkeeper/internal/model"
)

// TestUpdateScratchPadReqVersion checks that the version is optional (older
// clients keep last-write-wins) and that version 0 counts as given.
func TestUpdateScratchPadReqVersion(t *testing.T) {
	cases := []struct {
		body        string
		wantContent string
		wantVersion *int
	}{
		{`{"content":"creds on 10.0.0.5"}`, "creds on 10.0.0.5", nil},
		{`{"content":"creds on 10.0.0.5","version":0}`, "creds on 10.0.0.5", intPtr(0)},
		{`{"content":"","version":4}`, "", intPtr(4)},
		{`{"content":"x","version":null}`, "x", nil},
	}
	for _, tc := range cases {
		var req updateScratchPadReq
		if err := binding.JSON.BindBody([]byte(tc.body), &req); err != nil {
			t.Fatalf("bind %s: %v", tc.body, err)
		}
		if req.Content == nil || *req.Content != tc.wantContent {
			t.Errorf("%s: Content = %v, want %q", tc.body, req.Content, tc.wantContent)
		}
		if (req.Version == nil) != (tc.wantVersion == nil) ||
			(req.Version != nil && *req.Version != *tc.wantVersion) {
			t.Errorf("%s: Version = %v, want %v", tc.body, deref(req.Version), deref(tc.wantVersion))
		}
	}
}

// TestUpdateScratchPadReqColumns checks that a body without content changes
// nothing (the handler answers 400) instead of clearing the scratch pad,
// while an explicitly empty content still clears it.
func TestUpdateScratchPadReqColumns(t *testing.T) {
	for _, body := range []string{`{}`, `{"version":3}`, `{"content":null,"version":3}`, `{"save_id":"abc"}`} {
		var req updateScratchPadReq
		if err := binding.JSON.BindBody([]byte(body), &req); err != nil {
			t.Fatalf("bind %s: %v", body, err)
		}
		if cols := req.columns(); cols != nil {
			t.Errorf("%s: columns() = %v, want nil", body, cols)
		}
	}

	var req updateScratchPadReq
	if err := binding.JSON.BindBody([]byte(`{"content":"","version":2,"save_id":"s1"}`), &req); err != nil {
		t.Fatal(err)
	}
	cols := req.columns()
	if cols["scratch_pad"] != "" || cols["scratch_pad_save_id"] != "s1" || len(cols) != 3 {
		t.Errorf("columns() = %v", cols)
	}
	if expr, ok := cols["scratch_pad_version"].(clause.Expr); !ok || expr.SQL != "scratch_pad_version + 1" {
		t.Errorf("scratch_pad_version column = %#v", cols["scratch_pad_version"])
	}

	// An older client sends no save_id: the stored id is reset.
	req = updateScratchPadReq{}
	if err := binding.JSON.BindBody([]byte(`{"content":"x"}`), &req); err != nil {
		t.Fatal(err)
	}
	if cols := req.columns(); cols["scratch_pad_save_id"] != "" {
		t.Errorf("scratch_pad_save_id = %v, want empty", cols["scratch_pad_save_id"])
	}
}

// TestScratchPadSaveGuard pins the WHERE clause of a versioned scratch pad
// save, with and without unconfirmed earlier saves.
func TestScratchPadSaveGuard(t *testing.T) {
	if _, _, ok := scratchPadSaveGuard.where(nil, []string{"a"}); ok {
		t.Error("no version: want an unconditional save")
	}
	q, args, ok := scratchPadSaveGuard.where(intPtr(4), nil)
	if !ok || q != "scratch_pad_version = ?" || len(args) != 1 || args[0] != 4 {
		t.Errorf("where(4) = %q %v %v", q, args, ok)
	}
	q, args, ok = scratchPadSaveGuard.where(intPtr(4), []string{"a", "b"})
	if !ok || q != "(scratch_pad_version = ? OR scratch_pad_save_id IN ?)" || len(args) != 2 || args[0] != 4 {
		t.Errorf("where(4, ids) = %q %v %v", q, args, ok)
	}
	if ids, _ := args[1].([]string); len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Errorf("ids arg = %#v", args[1])
	}
}

// TestScratchPadConflictBody pins the 409 shape the overview reads to offer
// "Load latest" / "Keep mine".
func TestScratchPadConflictBody(t *testing.T) {
	body := scratchPadConflictBody(model.Assessment{ScratchPad: "newer text", ScratchPadVersion: 9, ScratchPadSaveID: "s9"})
	if body["error"] != "scratch pad changed elsewhere" || body["scratch_pad"] != "newer text" ||
		body["scratch_pad_version"] != 9 || body["scratch_pad_save_id"] != "s9" || len(body) != 4 {
		t.Errorf("scratchPadConflictBody = %v", body)
	}
}

// TestRowFound checks how a lookup error maps to found / not found / failed:
// only a missing row is "not found" (a 404); any other error is reported as
// a failure (a 500).
func TestRowFound(t *testing.T) {
	dbErr := errors.New(`pq: relation "hosts" does not exist`)
	cases := []struct {
		name      string
		err       error
		wantFound bool
		wantErr   error
	}{
		{"found", nil, true, nil},
		{"missing row", gorm.ErrRecordNotFound, false, nil},
		{"wrapped missing row", fmt.Errorf("lookup: %w", gorm.ErrRecordNotFound), false, nil},
		{"database error", dbErr, false, dbErr},
	}
	for _, tc := range cases {
		found, err := rowFound(tc.err)
		if found != tc.wantFound || err != tc.wantErr {
			t.Errorf("%s: rowFound = (%v, %v), want (%v, %v)", tc.name, found, err, tc.wantFound, tc.wantErr)
		}
	}
}
