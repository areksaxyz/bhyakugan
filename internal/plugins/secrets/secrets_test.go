package secrets

import (
	"testing"

	"github.com/yupiyy/bhyakugan/internal/core"
)

func TestDetectInContent_DocsBackupReferenceIsIgnored(t *testing.T) {
	content := `How to backup DB: mysqldump -u user -p db > backup.sql`
	var findings []core.Finding

	DetectInContent(content, "https://example.com/docs", func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for docs reference, got %d: %+v", len(findings), findings)
	}
}
