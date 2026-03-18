package core

import "testing"

func TestNormalizeFindingConfidence(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want FindingConfidence
	}{
		{name: "empty defaults probable", raw: "", want: ConfidenceProbable},
		{name: "mixed case confirmed", raw: " ConFiRMed ", want: ConfidenceConfirmed},
		{name: "mixed case noisy", raw: " NOISY ", want: ConfidenceNoisy},
		{name: "unknown downgrades probable", raw: "validated", want: ConfidenceProbable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeFindingConfidence(tt.raw); got != tt.want {
				t.Fatalf("NormalizeFindingConfidence(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestFindingConfidenceHelpers(t *testing.T) {
	if got := FindingConfidence("confirmed").DisplayLabel(); got != "CONFIRMED" {
		t.Fatalf("DisplayLabel() = %q, want %q", got, "CONFIRMED")
	}

	if got := ConfidenceRank(ConfidenceConfirmed); got <= ConfidenceRank(ConfidenceProbable) {
		t.Fatalf("expected confirmed rank > probable rank")
	}

	if got := ConfidenceRank(ConfidenceProbable); got <= ConfidenceRank(ConfidenceNoisy) {
		t.Fatalf("expected probable rank > noisy rank")
	}
}

func TestBucketLabelsStayCanonical(t *testing.T) {
	tests := []struct {
		bucket FindingBucket
		want   string
	}{
		{bucket: BucketValidated, want: "Validated Public Exposures"},
		{bucket: BucketProbable, want: "Probable Sensitive Signals"},
		{bucket: BucketRecon, want: "Recon / Attack Surface"},
	}

	for _, tt := range tests {
		if got := DisplayBucketLabel(tt.bucket); got != tt.want {
			t.Fatalf("DisplayBucketLabel(%q) = %q, want %q", tt.bucket, got, tt.want)
		}
	}
}
