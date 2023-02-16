package aes

import (
	"crypto"
	"crypto/rand"
	gorsa "crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/prairir/encryptdir/pkg/rsa"
)

// aes.GenKeyList: Generates a list of `keySize` sized keys
// if keySize random keys of random size
func GenKeyList(keySize uint64, length int) ([][]byte, error) {
	keyList := make([][]byte, length)

	for i := 0; i < len(keyList); i++ {
		keyS := keySize
		if keySize == 0 {
			n, err := rand.Int(rand.Reader, big.NewInt(3))
			if err != nil {
				return [][]byte{}, fmt.Errorf("aes.GenKeyList: iteration = %d:, rand.Int: %w", i, err)
			}

			n64 := n.Uint64()

			// change 0/1/2 => 128/196/256
			// Example:
			// 128 = 0b010000000 + (0) = 128
			// 128 = 0b010000000 => 0b010000000 + (0b001000000) =  0b011000000 = 192
			// 128 = 0b010000000 => 0b010000000 + (0b010000000) =  0b100000000 = 256
			// 0b100000000 = 256
			keyS = (128 + (64 * n64))
		}

		keyList[i] = make([]byte, keyS)

		// to get rid of a stupid error
		// go that shouldnt be an error wtf
		var err error
		keyList[i], err = GenKey(uint(keyS))
		if err != nil {
			return [][]byte{}, fmt.Errorf("aes.GenKeyList: iteration = %d: aes.GenKey: %w", i, err)
		}
	}

	return keyList, nil
}

// aes.GenKey: generate a random aes key of length `size` in bits
func GenKey(size uint) ([]byte, error) {
	key := make([]byte, size/8)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("aes.GenKey: rand.Read: %w", err)
	}

	return key, nil
}

func WriteKeys(keyMap map[string][]byte, privKey *gorsa.PrivateKey, outpath string) error {
	// create file, error if already exist
	out, err := os.OpenFile(outpath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("aes.WriteKeys: os.OpenFile: outpath = %q : %w", outpath, err)
	}
	defer out.Close()

	payload, err := json.Marshal(keyMap)
	if err != nil {
		return fmt.Errorf("aes.WriteKeys: json.Marhsal: %w", err)
	}

	// look i dont want to use md5 either, it was specified for this :(
	signature, err := rsa.CreateSignature(privKey, payload, crypto.MD5)
	if err != nil {
		return fmt.Errorf("aes.WriteKeys: rsa.CreateSignature: %w", err)
	}

	payload = append(signature, payload...)

	payload, err = gorsa.EncryptOAEP(crypto.MD5.New(), rand.Reader, &privKey.PublicKey, payload, []byte("keys"))
	if err != nil {
		return fmt.Errorf("aes.WriteKeys: gorsa.EncryptOAEP: %w", err)
	}

	_, err = out.Write(payload)
	if err != nil {
		return fmt.Errorf("aes.WriteKeys: out.Write: %w", err)
	}

	return nil
}

func ReadKeys(privKey *gorsa.PrivateKey, inpath string) (map[string][]byte, error) {
	in, err := os.OpenFile(inpath, os.O_RDONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("aes.ReadKeys: os.OpenFile: %w", err)
	}
	defer in.Close()

	encPayload, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("aes.ReadKeys: io.ReadAll: %w", err)
	}

	payload, err := gorsa.DecryptOAEP(crypto.MD5.New(), rand.Reader, privKey, encPayload, []byte("keys"))
	if err != nil {
		return nil, fmt.Errorf("aes.ReadKeys: gorsa.DecryptOAEP: %w", err)
	}

	sig := payload[:128]
	err = rsa.VerifySignature(&privKey.PublicKey, sig, payload[128:], crypto.MD5)
	if err != nil {
		return nil, fmt.Errorf("aes.ReadKeys: rsa.VerifySignature: %w", err)
	}

	// get rid of signature
	payload = payload[:128]

	keyMap := make(map[string][]byte)
	err = json.Unmarshal(payload, &keyMap)
	if err != nil {
		return nil, fmt.Errorf("aes.ReadKeys: json.Unmarshal: %w", err)
	}
	return keyMap, nil
}
