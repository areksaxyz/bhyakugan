package main

import (
	"fmt"
	"regexp"
)

func main() {
	pattern := `(?i)(?:aws_secret|aws_secret_access_key|secret_key|secret_access_key).{0,20}\b([0-9a-zA-Z/+=]{40})\b`
	re := regexp.MustCompile(pattern)
	text := `const aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";`
	
	matches := re.FindAllStringSubmatch(text, -1)
	if len(matches) > 0 {
		fmt.Printf("Match found: %v\n", matches[0])
	} else {
		fmt.Println("No match found")
	}
}
