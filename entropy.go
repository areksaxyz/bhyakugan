package main

import (
	"fmt"
	"math"
)

func main() {
	key := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	freq := make(map[rune]float64)
	for _, c := range key {
		freq[c]++
	}
	var entropy float64
	length := float64(len(key))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	fmt.Printf("Entropy: %f
", entropy)
}