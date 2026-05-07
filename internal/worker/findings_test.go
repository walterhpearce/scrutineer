package worker

import "testing"

func TestToFindings_carriesReachabilityAndQualityTier(t *testing.T) {
	raw := []byte(`{
	  "findings": [{
	    "id": "F1", "sinks": ["S1"], "title": "heap overflow in parse",
	    "severity": "High", "cwe": "CWE-787", "location": "src/parse.c:42",
	    "reachability": "harness_only", "quality_tier": "high",
	    "trace": "t", "boundary": "b", "validation": "v", "rating": "r"
	  }]
	}`)
	rep, err := parseReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	got := rep.toFindings(1, 1, "abc", "")
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Reachability != "harness_only" {
		t.Errorf("Reachability = %q, want harness_only", got[0].Reachability)
	}
	if got[0].QualityTier != "high" {
		t.Errorf("QualityTier = %q, want high", got[0].QualityTier)
	}
}

func TestParseReport_toleratesNonStringTopLevelFields(t *testing.T) {
	// #172: models sometimes copy context.json's repository object (and invent
	// an artefact object) into report.json. Only findings[] is consumed, so
	// the parser must not fail on the shape of fields it never reads.
	raw := []byte(`{
		"repository": {"url": "https://github.com/x/y.git", "name": "y"},
		"artefact": {"name": "y", "version": "1.2.3"},
		"languages": "rust",
		"spec_version": "10",
		"findings": [
			{"id": "F1", "title": "t", "severity": "Low", "cwe": "CWE-20",
			 "location": "src/a.rs:10", "sinks": ["S1"],
			 "trace": "x", "boundary": "x", "validation": "x", "rating": "x"}
		]
	}`)
	r, err := parseReport(raw)
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("len(Findings) = %d, want 1", len(r.Findings))
	}
	if r.Findings[0].ID != "F1" || r.Findings[0].Title != "t" {
		t.Errorf("finding not extracted: %+v", r.Findings[0])
	}
}

func TestParseReport_stringTopLevelFieldsStillWork(t *testing.T) {
	raw := []byte(`{
		"repository": "https://github.com/x/y.git",
		"artefact": "pkg:cargo/y@1.2.3",
		"findings": []
	}`)
	r, err := parseReport(raw)
	if err != nil {
		t.Fatalf("parseReport: %v", err)
	}
	if len(r.Findings) != 0 {
		t.Errorf("len(Findings) = %d, want 0", len(r.Findings))
	}
}
