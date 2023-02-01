package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle" // Use should trigger great care
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh"
)

const (
	hmacPrefix        = "hmac"
	rsaPrefix         = "rsa"
	sshPrefix         = "ssh"
	ecdsaPrefix       = "ecdsa"
	ed25519Prefix     = "ed25519"
	md4String         = "md4"
	md5String         = "md5"
	sha1String        = "sha1"
	sha224String      = "sha224"
	sha256String      = "sha256"
	sha384String      = "sha384"
	sha512String      = "sha512"
	md5sha1String     = "md5sha1"
	ripemd160String   = "ripemd160"
	sha3_224String    = "sha3-224"
	sha3_256String    = "sha3-256"
	sha3_384String    = "sha3-384"
	sha3_512String    = "sha3-512"
	sha512_224String  = "sha512-224"
	sha512_256String  = "sha512-256"
	blake2s_256String = "blake2s-256"
	blake2b_256String = "blake2b-256"
	blake2b_384String = "blake2b-384"
	blake2b_512String = "blake2b-512"
)

var blake2Algorithms = map[crypto.Hash]bool{
	crypto.BLAKE2s_256: true,
	crypto.BLAKE2b_256: true,
	crypto.BLAKE2b_384: true,
	crypto.BLAKE2b_512: true,
}

var hashToDef = map[crypto.Hash]struct {
	name string
	new  func(key []byte) (hash.Hash, error) // Only MACers will accept a key
}{
	// Which standard names these?
	// The spec lists the following as a canonical reference, which is dead:
	// http://www.iana.org/assignments/signature-algorithms
	//
	// Note that the forbidden hashes have an invalid 'new' function.
	crypto.MD4: {md4String, func(key []byte) (hash.Hash, error) { return nil, nil }},
	crypto.MD5: {md5String, func(key []byte) (hash.Hash, error) { return nil, nil }},
	// Temporarily enable SHA1 because of issue https://github.com/golang/go/issues/37278
	crypto.SHA1:        {sha1String, func(key []byte) (hash.Hash, error) { return sha1.New(), nil }},
	crypto.SHA224:      {sha224String, func(key []byte) (hash.Hash, error) { return sha256.New224(), nil }},
	crypto.SHA256:      {sha256String, func(key []byte) (hash.Hash, error) { return sha256.New(), nil }},
	crypto.SHA384:      {sha384String, func(key []byte) (hash.Hash, error) { return sha512.New384(), nil }},
	crypto.SHA512:      {sha512String, func(key []byte) (hash.Hash, error) { return sha512.New(), nil }},
	crypto.MD5SHA1:     {md5sha1String, func(key []byte) (hash.Hash, error) { return nil, nil }},
	crypto.RIPEMD160:   {ripemd160String, func(key []byte) (hash.Hash, error) { return ripemd160.New(), nil }},
	crypto.SHA3_224:    {sha3_224String, func(key []byte) (hash.Hash, error) { return sha3.New224(), nil }},
	crypto.SHA3_256:    {sha3_256String, func(key []byte) (hash.Hash, error) { return sha3.New256(), nil }},
	crypto.SHA3_384:    {sha3_384String, func(key []byte) (hash.Hash, error) { return sha3.New384(), nil }},
	crypto.SHA3_512:    {sha3_512String, func(key []byte) (hash.Hash, error) { return sha3.New512(), nil }},
	crypto.SHA512_224:  {sha512_224String, func(key []byte) (hash.Hash, error) { return sha512.New512_224(), nil }},
	crypto.SHA512_256:  {sha512_256String, func(key []byte) (hash.Hash, error) { return sha512.New512_256(), nil }},
	crypto.BLAKE2s_256: {blake2s_256String, func(key []byte) (hash.Hash, error) { return blake2s.New256(key) }},
	crypto.BLAKE2b_256: {blake2b_256String, func(key []byte) (hash.Hash, error) { return blake2b.New256(key) }},
	crypto.BLAKE2b_384: {blake2b_384String, func(key []byte) (hash.Hash, error) { return blake2b.New384(key) }},
	crypto.BLAKE2b_512: {blake2b_512String, func(key []byte) (hash.Hash, error) { return blake2b.New512(key) }},
}

var stringToHash map[string]crypto.Hash

const (
	defaultAlgorithm        = RSA_SHA256
	defaultAlgorithmHashing = sha256String
)

func init() {
	stringToHash = make(map[string]crypto.Hash, len(hashToDef))
	for k, v := range hashToDef {
		stringToHash[v.name] = k
	}
	// This should guarantee that at runtime the defaultAlgorithm will not
	// result in errors when fetching a macer or signer (see algorithms.go)
	if ok, err := isAvailable(string(defaultAlgorithmHashing)); err != nil {
		panic(err)
	} else if !ok {
		panic(fmt.Sprintf("the default httpsig algorithm is unavailable: %q", defaultAlgorithm))
	}
}

func isForbiddenHash(h crypto.Hash) bool {
	switch h {
	// Not actually cryptographically secure
	case crypto.MD4:
		fallthrough
	case crypto.MD5:
		fallthrough
	case crypto.MD5SHA1: // shorthand for crypto/tls, not actually implemented
		return true
	}
	// Still cryptographically secure
	return false
}

var _ SigningMethod = &hmacAlgorithm{}

type hmacAlgorithm struct {
	fn   func(key []byte) (hash.Hash, error)
	kind crypto.Hash
}

func (h *hmacAlgorithm) Sign(key interface{}, data []byte) ([]byte, error) {
	keyb, ok := key.([]byte)
	if !ok {
		return nil, errors.New("key is not a slice of bytes")
	}
	hs, err := h.fn(keyb)
	if err != nil {
		return nil, err
	}

	if err = setSig(hs, data); err != nil {
		return nil, err
	}
	return hs.Sum(nil), nil
}

func (h *hmacAlgorithm) Verify(key interface{}, data, signature []byte) error {
	keyb, ok := key.([]byte)
	if !ok {
		return errors.New("key is not a slice of bytes")
	}

	hs, err := h.fn(keyb)
	if err != nil {
		return err
	}
	defer hs.Reset()
	err = setSig(hs, data)
	if err != nil {
		return err
	}
	expected := hs.Sum(nil)
	if hmac.Equal(signature, expected) {
		return nil
	}

	return ErrInvalidSignature
}

func (h *hmacAlgorithm) String() string {
	return fmt.Sprintf("%s-%s", hmacPrefix, hashToDef[h.kind].name)
}

var _ SigningMethod = &rsaAlgorithm{}

type rsaAlgorithm struct {
	hash.Hash
	kind      crypto.Hash
	sshSigner ssh.Signer
}

func (r *rsaAlgorithm) setSig(b []byte) error {
	n, err := r.Write(b)
	if err != nil {
		r.Reset()
		return err
	} else if n != len(b) {
		r.Reset()
		return fmt.Errorf("could only write %d of %d bytes of signature to hash", n, len(b))
	}
	return nil
}

func (r *rsaAlgorithm) Sign(key interface{}, data []byte) ([]byte, error) {
	if r.sshSigner != nil {
		sshsig, err := r.sshSigner.Sign(rand.Reader, data)
		if err != nil {
			return nil, err
		}

		return sshsig.Blob, nil
	}
	defer r.Reset()

	if err := r.setSig(data); err != nil {
		return nil, err
	}
	rsaK, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not *rsa.PrivateKey")
	}
	return rsa.SignPKCS1v15(rand.Reader, rsaK, r.kind, r.Sum(nil))
}

func (r *rsaAlgorithm) Verify(key interface{}, data, signature []byte) error {
	defer r.Reset()
	rsaK, ok := key.(*rsa.PublicKey)
	if !ok {
		return errors.New("key is not *rsa.PublicKey")
	}
	if err := r.setSig(data); err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(rsaK, r.kind, r.Sum(nil), signature)
}

func (r *rsaAlgorithm) String() string {
	return fmt.Sprintf("%s-%s", rsaPrefix, hashToDef[r.kind].name)
}

var _ SigningMethod = &ed25519Algorithm{}

type ed25519Algorithm struct {
	sshSigner ssh.Signer
}

func (r *ed25519Algorithm) Sign(key interface{}, data []byte) ([]byte, error) {
	if r.sshSigner != nil {
		sshsig, err := r.sshSigner.Sign(rand.Reader, data)
		if err != nil {
			return nil, err
		}

		return sshsig.Blob, nil
	}
	ed25519K, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("key is not ed25519.PrivateKey")
	}
	return ed25519.Sign(ed25519K, data), nil
}

func (r *ed25519Algorithm) Verify(key interface{}, data, signature []byte) error {
	ed25519K, ok := key.(ed25519.PublicKey)
	if !ok {
		return errors.New("key is not ed25519.PublicKey")
	}

	if ed25519.Verify(ed25519K, data, signature) {
		return nil
	}

	return errors.New("ed25519 verify failed")
}

func (r *ed25519Algorithm) String() string {
	return fmt.Sprintf("%s", ed25519Prefix)
}

var _ SigningMethod = &ecdsaAlgorithm{}

type ecdsaAlgorithm struct {
	hash.Hash
	kind crypto.Hash
}

func (r *ecdsaAlgorithm) setSig(b []byte) error {
	n, err := r.Write(b)
	if err != nil {
		r.Reset()
		return err
	} else if n != len(b) {
		r.Reset()
		return fmt.Errorf("could only write %d of %d bytes of signature to hash", n, len(b))
	}
	return nil
}

type ECDSASignature struct {
	R, S *big.Int
}

func (r *ecdsaAlgorithm) Sign(key interface{}, data []byte) ([]byte, error) {
	defer r.Reset()
	if err := r.setSig(data); err != nil {
		return nil, err
	}
	ecdsaK, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("key is not *ecdsa.PrivateKey")
	}

	return ecdsa.SignASN1(rand.Reader, ecdsaK, r.Sum(nil))
}

func (r *ecdsaAlgorithm) Verify(key interface{}, data, signature []byte) error {
	defer r.Reset()
	ecdsaK, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("crypto.PublicKey is not *ecdsa.PublicKey")
	}
	if err := r.setSig(data); err != nil {
		return err
	}

	if ecdsa.VerifyASN1(ecdsaK, r.Sum(nil), signature) {
		return nil
	}

	return errors.New("invalid signature")
}

func (r *ecdsaAlgorithm) String() string {
	return fmt.Sprintf("%s-%s", ecdsaPrefix, hashToDef[r.kind].name)
}

var _ SigningMethod = &blakeMacAlgorithm{}

type blakeMacAlgorithm struct {
	fn   func(key []byte) (hash.Hash, error)
	kind crypto.Hash
}

func (r *blakeMacAlgorithm) Sign(key interface{}, data []byte) ([]byte, error) {
	keyb, ok := key.([]byte)
	if !ok {
		return nil, errors.New("key is not a slice of bytes")
	}
	hs, err := r.fn(keyb)
	if err != nil {
		return nil, err
	}

	if err = setSig(hs, data); err != nil {
		return nil, err
	}
	return hs.Sum(nil), nil
}

func (r *blakeMacAlgorithm) Verify(key interface{}, data, signature []byte) error {
	keyb, ok := key.([]byte)
	if !ok {
		return errors.New("key is not a slice of bytes")
	}
	hs, err := r.fn(keyb)
	if err != nil {
		return err
	}
	defer hs.Reset()
	err = setSig(hs, data)
	if err != nil {
		return err
	}
	expected := hs.Sum(nil)
	if subtle.ConstantTimeCompare(signature, expected) == 1 {
		return nil
	}

	return ErrInvalidSignature
}

func (r *blakeMacAlgorithm) String() string {
	return fmt.Sprintf("%s", hashToDef[r.kind].name)
}

func setSig(a hash.Hash, b []byte) (err error) {
	defer func() {
		if err != nil {
			a.Reset()
		}
	}()
	n, err := a.Write(b)
	if err != nil {
		return err
	}

	if n != len(b) {
		return fmt.Errorf("could only write %d of %d bytes of signature to hash", n, len(b))
	}
	return nil
}

// IsSupportedHttpSigAlgorithm returns true if the string is supported by this
// library, is not a hash known to be weak, and is supported by the hardware.
func IsSupportedHttpSigAlgorithm(algo string) bool {
	a, err := isAvailable(algo)
	return a && err == nil
}

// isAvailable is an internally public function
func isAvailable(algo string) (bool, error) {
	c, ok := stringToHash[algo]
	if !ok {
		return false, fmt.Errorf("no match for %q", algo)
	}
	if isForbiddenHash(c) {
		return false, fmt.Errorf("forbidden hash type in %q", algo)
	}
	return c.Available(), nil
}

func newAlgorithmConstructor(algo string) (fn func(k []byte) (hash.Hash, error), c crypto.Hash, e error) {
	ok := false
	c, ok = stringToHash[algo]
	if !ok {
		e = fmt.Errorf("no match for %q", algo)
		return
	}
	if isForbiddenHash(c) {
		e = fmt.Errorf("forbidden hash type in %q", algo)
		return
	}
	algoDef, ok := hashToDef[c]
	if !ok {
		e = fmt.Errorf("have crypto.Hash %v but no definition", c)
		return
	}
	fn = func(key []byte) (hash.Hash, error) {
		h, err := algoDef.new(key)
		if err != nil {
			return nil, err
		}
		return h, nil
	}
	return
}

func newAlgorithm(algo string, key []byte) (hash.Hash, crypto.Hash, error) {
	fn, c, err := newAlgorithmConstructor(algo)
	if err != nil {
		return nil, c, err
	}
	h, err := fn(key)
	return h, c, err
}

func signerFromSSHSigner(sshSigner ssh.Signer, s string) (SigningMethod, error) {
	switch {
	case strings.HasPrefix(s, rsaPrefix):
		return &rsaAlgorithm{
			sshSigner: sshSigner,
		}, nil
	case strings.HasPrefix(s, ed25519Prefix):
		return &ed25519Algorithm{
			sshSigner: sshSigner,
		}, nil
	default:
		return nil, fmt.Errorf("no signer matching %q", s)
	}
}
