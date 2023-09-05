package main

import (
	"fmt"
	"io"
	"os"

	"github.com/kylelemons/godebug/diff"
)

// Generate a diff between a string a a file.
func FileDiff(s string, fileToDiff string) (string, error) {
	// Open file.
	f, err := os.Open(fileToDiff)
	if err != nil {
		return "", fmt.Errorf("error opening file %s: %s", fileToDiff, err)
	}
	// Close file after done.
	defer f.Close()
	// Read all data from file.
	expected, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("error reading file %s: %s", fileToDiff, err)
	}

	// Compare expected file against provided string.
	return diff.Diff(string(expected), s), nil
}
