package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func GetKey(privKeyPath string, pubKeyPath string, password string) (*rsa.PrivateKey, error) {

	// try reading the private key
	privkey, err := ReadPrivateKey(privKeyPath, password)
	if err != nil {
		privkey, err := NewKeys(privKeyPath, pubKeyPath, password)
		if err != nil {
			return nil, fmt.Errorf("rsa.GetKey: %w", err)
		}
		return privkey, nil
	}
	// try reading the public key
	pubkey, err := ReadPublicKey(privKeyPath)
	if err != nil {
		privkey, err := NewKeys(privKeyPath, pubKeyPath, password)
		if err != nil {
			return nil, fmt.Errorf("rsa.GetKey: %w", err)
		}
		return privkey, nil
	}

	// ensuring the computed pubkey is equivalent to the read pubkey
	if !(pubkey.Equal(privkey.PublicKey)) {
		return nil, fmt.Errorf("rsa.GetKey: public key does not match private key")
	}
	return privkey, nil
}

func ReadPrivateKey(path string, password string) (*rsa.PrivateKey, error) {
	return nil, nil
}

func ReadPublicKey(path string) (*rsa.PublicKey, error) {
	return nil, nil
}

func NewKeys(privKeyPath string, pubKeyPath string, password string) (*rsa.PrivateKey, error) {
	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("rsa.GenerateKeys: rsa.GenerateKey: %w", err)
	}

	// write the keys to their respective files before we continue
	err = WriteKeysToFiles(rsakey, privKeyPath, pubKeyPath, password)
	if err != nil {
		return nil, fmt.Errorf("rsa.GetKey: %w", err)
	}

	return rsakey, nil
}

func WriteKeysToFiles(privateKey *rsa.PrivateKey, privPath string, pubPath string, password string) error {
	return nil
}
