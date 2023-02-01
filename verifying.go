package httpsig

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Verifier verifies HTTP Signatures.
//
// It will determine which of the supported headers has the parameters
// that define the signature.
//
// Verifiers are not safe to use between multiple goroutines.
//
// Note that verification ignores the deprecated 'algorithm' parameter.
type Verifier struct {
	header      http.Header
	kId         string
	signature   string
	created     int64
	expires     int64
	headers     []string
	sigStringFn func(http.Header, []string, int64, int64) (string, error)
}

// NewVerifier verifies the given request. It returns an error if the HTTP
// Signature parameters are not present in any headers, are present in more than
// one header, are malformed, or are missing required parameters. It ignores
// unknown HTTP Signature parameters.
func NewVerifier(r *http.Request) (*Verifier, error) {
	h := r.Header
	if _, hasHostHeader := h[hostHeader]; len(r.Host) > 0 && !hasHostHeader {
		h[hostHeader] = []string{r.Host}
	}
	return newVerifier(h, func(h http.Header, toInclude []string, created int64, expires int64) (string, error) {
		return signatureString(h, toInclude, addRequestTarget(r), created, expires)
	})
}

// NewResponseVerifier verifies the given response. It returns errors under the
// same conditions as NewVerifier.
func NewResponseVerifier(r *http.Response) (*Verifier, error) {
	return newVerifier(r.Header, func(h http.Header, toInclude []string, created int64, expires int64) (string, error) {
		return signatureString(h, toInclude, requestTargetNotPermitted, created, expires)
	})
}

func newVerifier(h http.Header, sigStringFn func(http.Header, []string, int64, int64) (string, error)) (*Verifier, error) {
	scheme, s, err := getSignatureScheme(h)
	if err != nil {
		return nil, err
	}
	kId, sig, headers, created, expires, err := getSignatureComponents(scheme, s)
	if created != 0 {
		//check if created is not in the future, we assume a maximum clock offset of 10 seconds
		now := time.Now().Unix()
		if created-now > 10 {
			return nil, errors.New("created is in the future")
		}
	}
	if expires != 0 {
		//check if expires is in the past, we assume a maximum clock offset of 10 seconds
		now := time.Now().Unix()
		if now-expires > 10 {
			return nil, errors.New("signature expired")
		}
	}
	if err != nil {
		return nil, err
	}
	return &Verifier{
		header:      h,
		kId:         kId,
		signature:   sig,
		created:     created,
		expires:     expires,
		headers:     headers,
		sigStringFn: sigStringFn,
	}, nil
}

// KeyId gets the public key id that the signature is signed with.
//
// Note that the application is expected to determine the algorithm
// used based on metadata or out-of-band information for this key id.
func (v *Verifier) KeyId() string {
	return v.kId
}

// Verify accepts the public key specified by KeyId and returns an
// error if verification fails or if the signature is malformed. The
// algorithm must be the one used to create the signature in order to
// pass verification. The algorithm is determined based on metadata or
// out-of-band information for the key id.
//
// If the signature was created using a MAC based algorithm, then the
// key is expected to be of type []byte. If the signature was created
// using an RSA based algorithm, then the public key is expected to be
// of type *rsa.PublicKey.
func (v *Verifier) Verify(key interface{}, algo Algorithm) error {
	method, err := newSigningMethod(algo)
	if err != nil {
		return fmt.Errorf("no crypto implementation available for %q: %s", algo, err)
	}

	data, err := v.sigStringFn(v.header, v.headers, v.created, v.expires)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(v.signature)
	if err != nil {
		return err
	}
	err = method.Verify(key, []byte(data), signature)
	if err != nil {
		return err
	}
	return nil
}

func getSignatureScheme(h http.Header) (scheme SignatureScheme, val string, err error) {
	s := h.Get(string(Signature))
	sigHasAll := strings.Contains(s, keyIdParameter) ||
		strings.Contains(s, headersParameter) ||
		strings.Contains(s, signatureParameter)
	a := h.Get(string(Authorization))
	authHasAll := strings.Contains(a, keyIdParameter) ||
		strings.Contains(a, headersParameter) ||
		strings.Contains(a, signatureParameter)
	if sigHasAll && authHasAll {
		err = fmt.Errorf("both %q and %q have signature parameters", Signature, Authorization)
		return
	} else if !sigHasAll && !authHasAll {
		err = fmt.Errorf("neither %q nor %q have signature parameters", Signature, Authorization)
		return
	} else if sigHasAll {
		val = s
		scheme = Signature
		return
	} else { // authHasAll
		val = a
		scheme = Authorization
		return
	}
}

func getSignatureComponents(scheme SignatureScheme, s string) (kId, sig string, headers []string, created int64, expires int64, err error) {
	if as := scheme.authScheme(); len(as) > 0 {
		s = strings.TrimPrefix(s, as+prefixSeparater)
	}
	params := strings.Split(s, parameterSeparater)
	for _, p := range params {
		kv := strings.SplitN(p, parameterKVSeparater, 2)
		if len(kv) != 2 {
			err = fmt.Errorf("malformed http signature parameter: %v", kv)
			return
		}
		k := kv[0]
		v := strings.Trim(kv[1], parameterValueDelimiter)
		switch k {
		case keyIdParameter:
			kId = v
		case createdKey:
			created, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				return
			}
		case expiresKey:
			expires, err = strconv.ParseInt(v, 10, 64)
			if err != nil {
				return
			}
		case algorithmParameter:
			// Deprecated, ignore
		case headersParameter:
			headers = strings.Split(v, headerParameterValueDelim)
		case signatureParameter:
			sig = v
		default:
			// Ignore unrecognized parameters
		}
	}
	if len(kId) == 0 {
		err = fmt.Errorf("missing %q parameter in http signature", keyIdParameter)
	} else if len(sig) == 0 {
		err = fmt.Errorf("missing %q parameter in http signature", signatureParameter)
	} else if len(headers) == 0 { // Optional
		headers = defaultHeaders
	}
	return
}
