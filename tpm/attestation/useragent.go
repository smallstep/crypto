package attestation

import "net/http"

// UserAgent is the value of the User-Agent HTTP header that will
// be set in HTTP requests to the attestation CA.
var UserAgent = "step-attestation-http-client/1.0"

// setUserAgent sets the User-Agent header in HTTP requests.
func setUserAgent(r *http.Request) {
	r.Header.Set("User-Agent", UserAgent)
}
