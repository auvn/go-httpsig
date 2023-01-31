package httpsig

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"strings"
)

var (
	ErrInvalidKey       = errors.New("invalid key")
	ErrInvalidSignature = errors.New("invalid signature")
)

type SigningMethod interface {
	Sign(key interface{}, data []byte) ([]byte, error)
	Verify(key interface{}, data, signature []byte) error
	String() string
}

func newSigningMethod(s string) (SigningMethod, error) {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, hmacPrefix) {
		algo := strings.TrimPrefix(s, hmacPrefix+"-")
		hashFn, cHash, err := newAlgorithmConstructor(algo)
		if err != nil {
			return nil, err
		}
		// Ensure below does not panic
		_, err = hashFn(nil)
		if err != nil {
			return nil, err
		}
		return &hmacAlgorithm{
			fn: func(key []byte) (hash.Hash, error) {
				return hmac.New(func() hash.Hash {
					h, e := hashFn(nil)
					if e != nil {
						panic(e)
					}
					return h
				}, key), nil
			},
			kind: cHash,
		}, nil
	} else if bl, ok := stringToHash[s]; ok && blake2Algorithms[bl] {
		hashFn, cHash, err := newAlgorithmConstructor(s)
		if err != nil {
			return nil, err
		}
		return &blakeMacAlgorithm{
			fn:   hashFn,
			kind: cHash,
		}, nil
	}
	isEcdsa := false
	isEd25519 := false
	var algo string
	if strings.HasPrefix(s, ecdsaPrefix) {
		algo = strings.TrimPrefix(s, ecdsaPrefix+"-")
		isEcdsa = true
	} else if strings.HasPrefix(s, rsaPrefix) {
		algo = strings.TrimPrefix(s, rsaPrefix+"-")
	} else if strings.HasPrefix(s, ed25519Prefix) {
		isEd25519 = true
		algo = "sha512"
	} else {
		return nil, fmt.Errorf("unknown signing method for %q", s)
	}
	hash, cHash, err := newAlgorithm(algo, nil)
	if err != nil {
		return nil, err
	}
	if isEd25519 {
		return &ed25519Algorithm{}, nil
	}
	if isEcdsa {
		return &ecdsaAlgorithm{
			Hash: hash,
			kind: cHash,
		}, nil
	}
	return &rsaAlgorithm{
		Hash: hash,
		kind: cHash,
	}, nil
}
