package saml

import "testing"

func TestShouldProbeSAMLEndpoint(t *testing.T) {
	if shouldProbeSAMLEndpoint("https://x/saml/acs", 200, "<html>generic callback</html>") {
		t.Fatal("expected generic 200 page without SAML signals to be ignored")
	}

	if !shouldProbeSAMLEndpoint("https://x/saml/acs", 200, "<html>SAML AssertionConsumerService</html>") {
		t.Fatal("expected 200 page with SAML signal to be probed")
	}

	if !shouldProbeSAMLEndpoint("https://x/saml/acs", 405, "") {
		t.Fatal("expected 405 endpoint to be probed")
	}

	if shouldProbeSAMLEndpoint("https://x/saml/acs", 302, "") {
		t.Fatal("expected 302 endpoint to be ignored")
	}
}
