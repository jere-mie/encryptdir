package rsa

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

// rsa.CreateSignature: hashes `payload` with `hashAlgo` then signs hashed `payload` with `key`
// returns: signature or error
func CreateSignature(key *rsa.PrivateKey, payload []byte, hashAlgo crypto.Hash) ([]byte, error) {
	h := hashAlgo.HashFunc().New()

	// doesnt return error
	h.Write(payload)

	signature, err := rsa.SignPKCS1v15(nil, key, hashAlgo, h.Sum(nil)[:])
	if err != nil {
		return nil, fmt.Errorf("rsa.CreateSignature: rsa.SignPKCS1v15: %w", err)
	}
	return signature, nil
}

// if err happens, signature isnt verified
func VerifySignature(key *rsa.PublicKey, signature []byte, payload []byte, hashAlgo crypto.Hash) error {
	h := hashAlgo.HashFunc().New()

	h.Write(payload)

	err := rsa.VerifyPKCS1v15(key, hashAlgo, h.Sum(nil)[:], signature)
	if err != nil {
		return fmt.Errorf("rsa.VerifySignature: rsa.VerifyPKCS1v15: %w", err)
	}
	return nil
}
