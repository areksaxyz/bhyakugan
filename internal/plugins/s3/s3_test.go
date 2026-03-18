package s3

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/areksaxyz/bhyakugan/internal/payloadrepo"
)

func TestMergedSensitiveFilesIncludeWordlistEntries(t *testing.T) {
	restoreS3WordlistsRoot(t)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("test"), 0644); err != nil {
		t.Fatalf("write README failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "verify"), 0755); err != nil {
		t.Fatalf("mkdir verify failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "verify", "file-interesting-names.txt"), []byte("tenant-export.ndjson\n"), 0644); err != nil {
		t.Fatalf("write file-interesting-names failed: %v", err)
	}
	payloadrepo.SetWordlistsRoot(root)

	for _, file := range mergedSensitiveFiles() {
		if file == "tenant-export.ndjson" {
			return
		}
	}
	t.Fatal("expected public storage scanner to load verify/file-interesting-names.txt")
}

func TestListingInterestingKeywordHitsUseWordlist(t *testing.T) {
	restoreS3WordlistsRoot(t)

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("test"), 0644); err != nil {
		t.Fatalf("write README failed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "verify"), 0755); err != nil {
		t.Fatalf("mkdir verify failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "verify", "response-interesting-keywords.txt"), []byte("swagger\nmetadata\n"), 0644); err != nil {
		t.Fatalf("write response-interesting-keywords failed: %v", err)
	}
	payloadrepo.SetWordlistsRoot(root)

	hits := listingInterestingKeywordHits(`{"items":[{"name":"swagger.json"},{"name":"metadata-backup.txt"}]}`)
	if len(hits) != 2 || hits[0] != "metadata" || hits[1] != "swagger" {
		t.Fatalf("expected keyword hits [metadata swagger], got %v", hits)
	}
}

func restoreS3WordlistsRoot(t *testing.T) {
	t.Helper()
	original := payloadrepo.WordlistsRoot()
	t.Cleanup(func() {
		if original != "" {
			payloadrepo.SetWordlistsRoot(original)
		}
	})
}
