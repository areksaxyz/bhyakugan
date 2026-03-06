package vulns

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yupiyy/bhyakugan/internal/core"
)

func TestScanOpenRedirect(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if target != "" {
			http.Redirect(w, r, target, 302)
		}
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := &http.Client{}
	
	t.Run("Vulnerable Parameter", func(t *testing.T) {
		found := false
		targetURL := ts.URL + "/redirect?url=ORIGINAL"
		
		ScanOpenRedirect(targetURL, client, func(f core.Finding) {
			if f.Type == "Open Redirect" {
				found = true
			}
		})

		if !found {
			t.Error("Expected Open Redirect finding, but none was found")
		}
	})

	t.Run("Non-Vulnerable Parameter", func(t *testing.T) {
		found := false
		targetURL := ts.URL + "/redirect?other=ORIGINAL"
		
		ScanOpenRedirect(targetURL, client, func(f core.Finding) {
			if f.Type == "Open Redirect" {
				found = true
			}
		})

		if found {
			t.Error("Did not expect Open Redirect finding for unrelated parameter")
		}
	})
}
