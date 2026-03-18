package core

import "strings"

type FindingBucket string

const (
	BucketValidated FindingBucket = "validated"
	BucketProbable  FindingBucket = "probable"
	BucketRecon     FindingBucket = "recon"
)

func NormalizeFindingBucket(raw string) FindingBucket {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case string(BucketValidated):
		return BucketValidated
	case string(BucketRecon):
		return BucketRecon
	default:
		return BucketProbable
	}
}

func DisplayBucketLabel(bucket FindingBucket) string {
	switch NormalizeFindingBucket(string(bucket)) {
	case BucketValidated:
		return "Validated Public Exposures"
	case BucketRecon:
		return "Recon / Attack Surface"
	default:
		return "Probable Sensitive Signals"
	}
}

type FindingConfidence string

const (
	ConfidenceConfirmed FindingConfidence = "confirmed"
	ConfidenceProbable  FindingConfidence = "probable"
	ConfidenceNoisy     FindingConfidence = "noisy"
)

func NormalizeFindingConfidence(raw string) FindingConfidence {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case string(ConfidenceConfirmed):
		return ConfidenceConfirmed
	case string(ConfidenceNoisy):
		return ConfidenceNoisy
	default:
		return ConfidenceProbable
	}
}

func (c FindingConfidence) Normalized() FindingConfidence {
	return NormalizeFindingConfidence(string(c))
}

func (c FindingConfidence) String() string {
	return string(c.Normalized())
}

func (c FindingConfidence) DisplayLabel() string {
	return strings.ToUpper(c.String())
}

func ConfidenceRank(confidence FindingConfidence) int {
	switch confidence.Normalized() {
	case ConfidenceConfirmed:
		return 3
	case ConfidenceProbable:
		return 2
	default:
		return 1
	}
}
