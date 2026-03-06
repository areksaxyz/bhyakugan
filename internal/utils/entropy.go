package utils

import (
	"math"
)

// CalculateShannonEntropy calculates the Shannon entropy of a string.
// A higher value indicates higher randomness/information density.
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	counts := make(map[rune]int)
	for _, char := range s {
		counts[char]++
	}

	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}

	return entropy
}
