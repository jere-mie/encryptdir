package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
)

// rsa.GetRSAKey: reads or generates an RSA key pair at `privKeyPath` and `pubKeyPath` respectively, encrypted by `password`
// returns: private key or error
func GetRSAKey(privKeyPath string, pubKeyPath string, password string) (*rsa.PrivateKey, error) {
	// try reading the private key
	privkey, err := ReadPrivateKey(privKeyPath, password)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("rsa.GetKey: %w", err)
		}
		privkey, err = NewKeys(privKeyPath, pubKeyPath, password)
		if err != nil {
			return nil, fmt.Errorf("rsa.GetKey: %w", err)
		}
		return privkey, nil
	}
	// try reading the public key
	pubkey, err := ReadPublicKey(pubKeyPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("rsa.GetKey: %w", err)
		}
		privkey, err = NewKeys(privKeyPath, pubKeyPath, password)
		if err != nil {
			return nil, fmt.Errorf("rsa.GetKey: %w", err)
		}
		return privkey, nil
	}

	// ensuring the computed pubkey is equivalent to the read pubkey
	if !(pubkey.Equal(&privkey.PublicKey)) {
		return nil, fmt.Errorf("rsa.GetKey: public key does not match private key")
	}
	return privkey, nil
}

// rsa.ReadPrivateKey: reads and decodes an RSA private key at `path`, encrypted by `password`
// returns: private key or error
func ReadPrivateKey(path string, password string) (*rsa.PrivateKey, error) {
	in, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("rsa.ReadPrivateKey: os.OpenFile: %w", err)
	}
	defer in.Close()

	encPayload, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("rsa.ReadPrivateKey: io.ReadAll: %w", err)
	}

	block, _ := pem.Decode(encPayload)
	if block == nil {
		return nil, fmt.Errorf("rsa.ReadPrivateKey: pem.Decode: no private key found")
	}

	decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("rsa.ReadPrivateKey: x509.DecryptPEMBlock: %w", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(decrypted)
	if err != nil {
		return nil, fmt.Errorf("rsa.ReadPrivateKey: x509.ParsePKCS1PrivateKey: %w", err)
	}
	return privateKey, nil
}

// rsa.ReadPublicKey: reads and decodes an RSA public key at `path`
// returns: public key or error
func ReadPublicKey(path string) (*rsa.PublicKey, error) {
	in, err := os.OpenFile(path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("rsa.ReadPublicKey: os.OpenFile: %w", err)
	}
	defer in.Close()

	encPayload, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("rsa.ReadPublicKey: io.ReadAll: %w", err)
	}

	block, _ := pem.Decode(encPayload)
	if block == nil {
		return nil, fmt.Errorf("rsa.ReadPublicKey: pem.Decode: no public key found")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("rsa.ReadPublicKey: x509.ParsePKCS1PrivateKey: %w", err)
	}
	return publicKey, nil
}

// rsa.NewKeys: generates private/public key, encrypted with `password`, and writes them to `privPath` and `pubPath` respectively
// returns: private key or error
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

// rsa.WriteKeysToFiles: writes `privatekey` to `privPath` and `privatekey.PublicKey` to `pubPath`
// returns: error
func WriteKeysToFiles(privateKey *rsa.PrivateKey, privPath string, pubPath string, password string) error {
	// create file, error if already exist
	outPriv, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("rsa.WriteKeysToFiles: os.OpenFile: outpath = %q : %w", privPath, err)
	}
	defer outPriv.Close()

	// create file, error if already exist
	outPub, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("rsa.WriteKeysToFiles: os.OpenFile: outpath = %q : %w", pubPath, err)
	}
	defer outPub.Close()

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	pubBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}

	// Encrypt the private key
	privBlock, err = x509.EncryptPEMBlock(rand.Reader, privBlock.Type, privBlock.Bytes, []byte(password), x509.PEMCipherAES256)
	if err != nil {
		return err
	}

	// write the private key
	err = pem.Encode(outPriv, privBlock)
	if err != nil {
		return fmt.Errorf("rsa.WriteKeysToFiles: pem.Encode: outpath = %q : %w", privPath, err)
	}

	// write the public key
	err = pem.Encode(outPub, pubBlock)
	if err != nil {
		return fmt.Errorf("rsa.WriteKeysToFiles: pem.Encode: outpath = %q : %w", pubPath, err)
	}

	return nil
}

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
