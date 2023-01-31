package httpsig

import (
	"net/http"
)

// Signers will sign HTTP requests or responses based on the algorithms and
// headers selected at creation time.
//
// Signers are not safe to use between multiple goroutines.
//
// Note that signatures do set the deprecated 'algorithm' parameter for
// backwards compatibility.
type SSHSigner interface {
	// SignRequest signs the request using ssh.Signer.
	// The public key id is used by the HTTP server to identify which key to use
	// to verify the signature.
	//
	// A Digest (RFC 3230) will be added to the request. The body provided
	// must match the body used in the request, and is allowed to be nil.
	// The Digest ensures the request body is not tampered with in flight,
	// and if the signer is created to also sign the "Digest" header, the
	// HTTP Signature will then ensure both the Digest and body are not both
	// modified to maliciously represent different content.
	SignRequest(pubKeyId string, r *http.Request, body []byte) error
	// SignResponse signs the response using ssh.Signer. The public key
	// id is used by the HTTP client to identify which key to use to verify
	// the signature.
	//
	// A Digest (RFC 3230) will be added to the response. The body provided
	// must match the body written in the response, and is allowed to be
	// nil. The Digest ensures the response body is not tampered with in
	// flight, and if the signer is created to also sign the "Digest"
	// header, the HTTP Signature will then ensure both the Digest and body
	// are not both modified to maliciously represent different content.
	SignResponse(pubKeyId string, r http.ResponseWriter, body []byte) error
}
