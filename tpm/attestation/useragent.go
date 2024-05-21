package attestation

import "net/http"

// UserAgent will set the User-Agent header in the client requests.
var UserAgent = "step-attestation-http-client/1.0"

func setUserAgent(r *http.Request) {
	r.Header.Set("User-Agent", UserAgent)
}
