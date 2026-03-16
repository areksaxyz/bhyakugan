package vulns

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/yupiyy/bhyakugan/internal/core"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestExtractUploadVerificationTargets(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Location": []string{"/uploads/bhyakugan_test.php"},
		},
	}

	body := `{"file_url":"https://example.com/files/bhyakugan_test.php","preview":"/media/bhyakugan_test.php"}`
	targets := extractUploadVerificationTargets("https://example.com/upload", resp, body)

	if len(targets) < 3 {
		t.Fatalf("expected multiple upload verification targets, got %v", targets)
	}
	if targets[0] != "https://example.com/uploads/bhyakugan_test.php" {
		t.Fatalf("unexpected first target: %v", targets[0])
	}
}

func TestVerifyUploadedMarker(t *testing.T) {
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body := "not found"
			status := 404
			if strings.Contains(req.URL.String(), "good.php") {
				body = "prefix BHYAKUGAN_UPLOAD_TEST_123 suffix"
				status = 200
			}
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	candidate, ok := verifyUploadedMarker([]string{
		"https://example.com/bad.php",
		"https://example.com/good.php",
	}, "BHYAKUGAN_UPLOAD_TEST_123", client)
	if !ok {
		t.Fatal("expected upload marker verification to succeed")
	}
	if candidate != "https://example.com/good.php" {
		t.Fatalf("unexpected verified candidate: %s", candidate)
	}
}

func TestUploadFindingRequiresRetrievalProof(t *testing.T) {
	var findings []core.Finding
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.Method {
			case http.MethodPost:
				return &http.Response{
					StatusCode: 201,
					Body:       io.NopCloser(strings.NewReader(`{"status":"success","file_url":"/uploads/bhyakugan_test.php"}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			case http.MethodGet:
				return &http.Response{
					StatusCode: 404,
					Body:       io.NopCloser(strings.NewReader("missing")),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			default:
				return &http.Response{
					StatusCode: 405,
					Body:       io.NopCloser(strings.NewReader("method not allowed")),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}
		}),
	}

	testUpload("https://example.com/upload", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Severity != "Medium" || findings[0].Confidence != "probable" {
		t.Fatalf("expected downgraded unverified finding, got severity=%s confidence=%s", findings[0].Severity, findings[0].Confidence)
	}
}

func TestUploadFindingConfirmedWhenRetrieved(t *testing.T) {
	var findings []core.Finding
	var marker string
	re := regexp.MustCompile(`BHYAKUGAN_UPLOAD_TEST_[0-9]+`)

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			switch req.Method {
			case http.MethodPost:
				body, _ := io.ReadAll(req.Body)
				marker = re.FindString(string(body))
				return &http.Response{
					StatusCode: 201,
					Body:       io.NopCloser(strings.NewReader(`{"status":"success","file_url":"/uploads/bhyakugan_test.php"}`)),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			case http.MethodGet:
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader("prefix " + marker + " suffix")),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			default:
				return &http.Response{
					StatusCode: 405,
					Body:       io.NopCloser(strings.NewReader("method not allowed")),
					Header:     make(http.Header),
					Request:    req,
				}, nil
			}
		}),
	}

	testUpload("https://example.com/upload", client, func(f core.Finding) {
		findings = append(findings, f)
	})

	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].Severity != "High" || findings[0].Confidence != "confirmed" {
		t.Fatalf("expected verified finding, got severity=%s confidence=%s", findings[0].Severity, findings[0].Confidence)
	}
	if findings[0].Target != "https://example.com/uploads/bhyakugan_test.php" {
		t.Fatalf("unexpected verified target: %s", findings[0].Target)
	}
}
