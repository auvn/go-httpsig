package httpsig

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	// Signature Parameters
	keyIdParameter            = "keyId"
	algorithmParameter        = "algorithm"
	headersParameter          = "headers"
	signatureParameter        = "signature"
	prefixSeparater           = " "
	parameterKVSeparater      = "="
	parameterValueDelimiter   = "\""
	parameterSeparater        = ","
	headerParameterValueDelim = " "
	// RequestTarget specifies to include the http request method and
	// entire URI in the signature. Pass it as a header to NewSigner.
	RequestTarget = "(request-target)"
	createdKey    = "created"
	expiresKey    = "expires"
	dateHeader    = "date"

	// Signature String Construction
	headerFieldDelimiter   = ": "
	headersDelimiter       = "\n"
	headerValueDelimiter   = ", "
	requestTargetSeparator = " "
)

var defaultHeaders = []string{dateHeader}

// Signers will sign HTTP requests or responses based on the algorithms and
// headers selected at creation time.
//
// Signers are not safe to use between multiple goroutines.
//
// Note that signatures do set the deprecated 'algorithm' parameter for
// backwards compatibility.
type Signer struct {
	method       SigningMethod
	makeDigest   bool
	dAlgo        DigestAlgorithm
	headers      []string
	targetHeader SignatureScheme
	prefix       string
	created      int64
	expires      int64
}

// NewSigner creates a new Signer with the provided algorithm preferences to
// make HTTP signatures. Only the first available algorithm will be used, which
// is returned by this function along with the Signer. If none of the preferred
// algorithms were available, then the default algorithm is used. The headers
// specified will be included into the HTTP signatures.
//
// The Digest will also be calculated on a request's body using the provided
// digest algorithm, if "Digest" is one of the headers listed.
//
// The provided scheme determines which header is populated with the HTTP
// Signature.
//
// An error is returned if an unknown or a known cryptographically insecure
// Algorithm is provided.
func NewSigner(
	prefs []Algorithm,
	dAlgo DigestAlgorithm,
	headers []string,
	scheme SignatureScheme,
	expiresIn int64,
) (*Signer, Algorithm, error) {
	m, algo, err := lookupSigningMethod(prefs)
	if err != nil {
		return nil, algo, err
	}
	s := newSigner(m, dAlgo, headers, scheme, expiresIn)
	return s, algo, nil
}

// NewwSSHSigner creates a new Signer using the specified ssh.Signer
// At the moment only ed25519 ssh keys are supported.
// The headers specified will be included into the HTTP signatures.
//
// The Digest will also be calculated on a request's body using the provided
// digest algorithm, if "Digest" is one of the headers listed.
//
// The provided scheme determines which header is populated with the HTTP
// Signature.
func NewSSHSigner(s ssh.Signer, dAlgo DigestAlgorithm, headers []string, scheme SignatureScheme, expiresIn int64) (SSHSigner, Algorithm, error) {
	sshAlgo := getSSHAlgorithm(s.PublicKey().Type())
	if sshAlgo == "" {
		return nil, "", fmt.Errorf("key type: %s not supported yet", s.PublicKey().Type())
	}

	signer, err := newSSHSigner(s, sshAlgo, dAlgo, headers, scheme, expiresIn)
	if err != nil {
		return nil, "", err
	}

	return signer, sshAlgo, nil
}

// SignRequest signs the request using a private key. The public key id
// is used by the HTTP server to identify which key to use to verify the
// signature.
//
// If the Signer was created using a MAC based algorithm, then the key
// is expected to be of type []byte. If the Signer was created using an
// RSA based algorithm, then the private key is expected to be of type
// *rsa.PrivateKey.
//
// A Digest (RFC 3230) will be added to the request. The body provided
// must match the body used in the request, and is allowed to be nil.
// The Digest ensures the request body is not tampered with in flight,
// and if the signer is created to also sign the "Digest" header, the
// HTTP Signature will then ensure both the Digest and body are not both
// modified to maliciously represent different content.
func (s *Signer) SignRequest(
	pKey crypto.PrivateKey,
	pubKeyId string,
	r *http.Request,
	body []byte,
) error {
	if body != nil {
		err := addDigest(r, s.dAlgo, body)
		if err != nil {
			return err
		}
	}
	data, err := s.signatureString(r)
	if err != nil {
		return err
	}
	enc, err := s.signSignature(pKey, data)
	if err != nil {
		return err
	}

	setSignatureHeader(
		r.Header,
		string(s.targetHeader),
		s.prefix,
		pubKeyId,
		s.method.String(),
		enc,
		s.headers,
		s.created,
		s.expires)
	return nil
}

// SignResponse signs the response using a private key. The public key
// id is used by the HTTP client to identify which key to use to verify
// the signature.
//
// If the Signer was created using a MAC based algorithm, then the key
// is expected to be of type []byte. If the Signer was created using an
// RSA based algorithm, then the private key is expected to be of type
// *rsa.PrivateKey.
//
// A Digest (RFC 3230) will be added to the response. The body provided
// must match the body written in the response, and is allowed to be
// nil. The Digest ensures the response body is not tampered with in
// flight, and if the signer is created to also sign the "Digest"
// header, the HTTP Signature will then ensure both the Digest and body
// are not both modified to maliciously represent different content.
func (s *Signer) SignResponse(pKey crypto.PrivateKey, pubKeyId string, r http.ResponseWriter, body []byte) error {
	if body != nil {
		err := addDigestResponse(r, s.dAlgo, body)
		if err != nil {
			return err
		}
	}
	data, err := s.signatureStringResponse(r)
	if err != nil {
		return err
	}
	enc, err := s.signSignature(pKey, data)
	if err != nil {
		return err
	}
	setSignatureHeader(r.Header(), string(s.targetHeader), s.prefix, pubKeyId, s.method.String(), enc, s.headers, s.created, s.expires)
	return nil
}

func (s *Signer) signSignature(pKey crypto.PrivateKey, data string) (string, error) {
	sig, err := s.method.Sign(pKey, []byte(data))
	if err != nil {
		return "", err
	}
	enc := base64.StdEncoding.EncodeToString(sig)
	return enc, nil
}

func (s *Signer) signatureString(r *http.Request) (string, error) {
	return signatureString(
		r.Header, s.headers, addRequestTarget(r), s.created, s.expires)
}

func (s *Signer) signatureStringResponse(r http.ResponseWriter) (string, error) {
	return signatureString(
		r.Header(), s.headers, requestTargetNotPermitted, s.created, s.expires)
}

var _ SSHSigner = &asymmSSHSigner{}

type asymmSSHSigner struct {
	*Signer
}

func (a *asymmSSHSigner) SignRequest(pubKeyId string, r *http.Request, body []byte) error {
	return a.Signer.SignRequest(nil, pubKeyId, r, body)
}

func (a *asymmSSHSigner) SignResponse(pubKeyId string, r http.ResponseWriter, body []byte) error {
	return a.Signer.SignResponse(nil, pubKeyId, r, body)
}

func setSignatureHeader(h http.Header, targetHeader, prefix, pubKeyId, algo, enc string, headers []string, created int64, expires int64) {
	if len(headers) == 0 {
		headers = defaultHeaders
	}
	var b bytes.Buffer
	// KeyId
	b.WriteString(prefix)
	if len(prefix) > 0 {
		b.WriteString(prefixSeparater)
	}
	b.WriteString(keyIdParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	b.WriteString(pubKeyId)
	b.WriteString(parameterValueDelimiter)
	b.WriteString(parameterSeparater)
	// Algorithm
	b.WriteString(algorithmParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	b.WriteString("hs2019") //real algorithm is hidden, see newest version of spec draft
	b.WriteString(parameterValueDelimiter)
	b.WriteString(parameterSeparater)

	hasCreated := false
	hasExpires := false
	for _, h := range headers {
		val := strings.ToLower(h)
		if val == "("+createdKey+")" {
			hasCreated = true
		} else if val == "("+expiresKey+")" {
			hasExpires = true
		}
	}

	// Created
	if hasCreated == true {
		b.WriteString(createdKey)
		b.WriteString(parameterKVSeparater)
		b.WriteString(strconv.FormatInt(created, 10))
		b.WriteString(parameterSeparater)
	}

	// Expires
	if hasExpires == true {
		b.WriteString(expiresKey)
		b.WriteString(parameterKVSeparater)
		b.WriteString(strconv.FormatInt(expires, 10))
		b.WriteString(parameterSeparater)
	}

	// Headers
	b.WriteString(headersParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	for i, h := range headers {
		b.WriteString(strings.ToLower(h))
		if i != len(headers)-1 {
			b.WriteString(headerParameterValueDelim)
		}
	}
	b.WriteString(parameterValueDelimiter)
	b.WriteString(parameterSeparater)
	// Signature
	b.WriteString(signatureParameter)
	b.WriteString(parameterKVSeparater)
	b.WriteString(parameterValueDelimiter)
	b.WriteString(enc)
	b.WriteString(parameterValueDelimiter)
	h.Add(targetHeader, b.String())
}

func requestTargetNotPermitted(b *bytes.Buffer) error {
	return fmt.Errorf("cannot sign with %q on anything other than an http request", RequestTarget)
}

func addRequestTarget(r *http.Request) func(b *bytes.Buffer) error {
	return func(b *bytes.Buffer) error {
		b.WriteString(RequestTarget)
		b.WriteString(headerFieldDelimiter)
		b.WriteString(strings.ToLower(r.Method))
		b.WriteString(requestTargetSeparator)
		b.WriteString(r.URL.Path)

		if r.URL.RawQuery != "" {
			b.WriteString("?")
			b.WriteString(r.URL.RawQuery)
		}

		return nil
	}
}

func signatureString(values http.Header, include []string, requestTargetFn func(b *bytes.Buffer) error, created int64, expires int64) (string, error) {
	if len(include) == 0 {
		include = defaultHeaders
	}
	var b bytes.Buffer
	for n, i := range include {
		i := strings.ToLower(i)
		if i == RequestTarget {
			err := requestTargetFn(&b)
			if err != nil {
				return "", err
			}
		} else if i == "("+expiresKey+")" {
			if expires == 0 {
				return "", fmt.Errorf("missing expires value")
			}
			b.WriteString(i)
			b.WriteString(headerFieldDelimiter)
			b.WriteString(strconv.FormatInt(expires, 10))
		} else if i == "("+createdKey+")" {
			if created == 0 {
				return "", fmt.Errorf("missing created value")
			}
			b.WriteString(i)
			b.WriteString(headerFieldDelimiter)
			b.WriteString(strconv.FormatInt(created, 10))
		} else {
			hv, ok := values[textproto.CanonicalMIMEHeaderKey(i)]
			if !ok {
				return "", fmt.Errorf("missing header %q", i)
			}
			b.WriteString(i)
			b.WriteString(headerFieldDelimiter)
			for i, v := range hv {
				b.WriteString(strings.TrimSpace(v))
				if i < len(hv)-1 {
					b.WriteString(headerValueDelimiter)
				}
			}
		}
		if n < len(include)-1 {
			b.WriteString(headersDelimiter)
		}
	}
	return b.String(), nil
}
