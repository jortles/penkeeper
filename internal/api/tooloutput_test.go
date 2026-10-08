package api

import (
	"testing"

	"github.com/google/uuid"
)

// TestPickPipeHost checks that identifiers written exactly like the target
// come first, that a pipe target never picks between hosts in different
// assessments (the same private address is common across clients), and that
// within one assessment the newest host wins (matches come newest first).
func TestPickPipeHost(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	host := func(ident string, aid uuid.UUID) pipeHost {
		return pipeHost{HostID: uuid.New(), HostIdentifier: ident, AssessmentID: aid, AssessmentName: aid.String()[:4]}
	}
	one := host("10.0.0.5", a)
	upper, lower := host("WEB01", a), host("web01", a)
	inA, inB, dupA := host("192.168.1.10", a), host("192.168.1.10", b), host("192.168.1.10", a)
	dcA, dcB := host("DC01.corp.local", a), host("dc01.corp.local", b)

	cases := []struct {
		name    string
		matches []pipeHost
		target  string
		want    *pipeHost
	}{
		{"none", nil, "10.0.0.5", nil},
		{"unique", []pipeHost{one}, "10.0.0.5", &one},
		{"unique ignoring case", []pipeHost{upper}, "web01", &upper},
		{"several assessments", []pipeHost{inA, inB}, "192.168.1.10", nil},
		{"several assessments, case-exact in one", []pipeHost{dcA, dcB}, "DC01.corp.local", &dcA},
		{"several assessments, case-exact in the other", []pipeHost{dcA, dcB}, "dc01.corp.local", &dcB},
		{"several assessments, no case-exact", []pipeHost{dcA, dcB}, "Dc01.Corp.Local", nil},
		{"several assessments, case-exact in both", []pipeHost{dcA, host("DC01.corp.local", b), dcB}, "DC01.corp.local", nil},
		{"one assessment, case-exact", []pipeHost{upper, lower}, "web01", &lower},
		{"one assessment, no case-exact: newest", []pipeHost{upper, lower}, "Web01", &upper},
		{"one assessment, duplicates: newest", []pipeHost{dupA, inA}, "192.168.1.10", &dupA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pickPipeHost(tc.matches, tc.target)
			if tc.want == nil {
				if ok {
					t.Fatalf("picked %+v, want no pick", got)
				}
				return
			}
			if !ok || got.HostID != tc.want.HostID {
				t.Fatalf("got %+v (ok=%v), want %+v", got, ok, *tc.want)
			}
		})
	}
}
