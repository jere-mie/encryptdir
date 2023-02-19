package aes

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	gorsa "crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/prairir/encryptdir/pkg/rsa"
)

const SIGNATURE_SIZE = 256

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

	// ripped from
	// https://stackoverflow.com/questions/62348923/rs256-message-too-long-for-rsa-public-key-size-error-signing-jwt
	step := privKey.PublicKey.Size() - 2*crypto.MD5.Size() - 2
	var encryptedBytes []byte

	for start := 0; start < len(payload); start += step {
		finish := start + step
		if finish > len(payload) {
			finish = len(payload)
		}

		encryptedBlockBytes, err := gorsa.EncryptOAEP(crypto.MD5.New(), rand.Reader, &privKey.PublicKey, payload[start:finish], []byte("keys"))
		if err != nil {
			return fmt.Errorf("aes.WriteKeys: gorsa.EncryptOAEP: %w", err)
		}

		encryptedBytes = append(encryptedBytes, encryptedBlockBytes...)
	}

	_, err = out.Write(encryptedBytes)
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

	// ripped from
	// https://stackoverflow.com/questions/62348923/rs256-message-too-long-for-rsa-public-key-size-error-signing-jwt
	msgLen := len(encPayload)
	step := privKey.PublicKey.Size()
	var decryptedBytes []byte

	for start := 0; start < msgLen; start += step {
		finish := start + step
		if finish > msgLen {
			finish = msgLen
		}

		decryptedBlockBytes, err := gorsa.DecryptOAEP(crypto.MD5.New(), rand.Reader, privKey, encPayload[start:finish], []byte("keys"))
		if err != nil {
			return nil, err
		}

		decryptedBytes = append(decryptedBytes, decryptedBlockBytes...)
	}
	payload := decryptedBytes

	sig := payload[:SIGNATURE_SIZE] // because rsa is 2048 sized
	err = rsa.VerifySignature(&privKey.PublicKey, sig, payload[SIGNATURE_SIZE:], crypto.MD5)
	if err != nil {
		return nil, fmt.Errorf("aes.ReadKeys: rsa.VerifySignature: %w", err)
	}

	// get rid of signature
	payload = payload[SIGNATURE_SIZE:]

	keyMap := make(map[string][]byte)
	err = json.Unmarshal(payload, &keyMap)
	if err != nil {
		return nil, fmt.Errorf("aes.ReadKeys: json.Unmarshal: %w", err)
	}
	return keyMap, nil
}

func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	var cipherBuf bytes.Buffer

	plainBuf := bytes.NewReader(plaintext)

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.Encrypt: aes.NewCipher: %w", err)
	}

	origSize := uint64(plainBuf.Size())
	err = binary.Write(&cipherBuf, binary.LittleEndian, &origSize)
	if err != nil {
		return nil, fmt.Errorf("aes.Encrypt: binary.Write: %w", err)
	}

	// Pad plaintext to a multiple of BlockSize with random padding.
	// ty eli
	if plainBuf.Size()%aes.BlockSize != 0 {
		bytesToPad := aes.BlockSize - (plainBuf.Size() % aes.BlockSize)
		padding := make([]byte, bytesToPad)
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("aes.Encrypt: rand.Read(padding): %w", err)
		}
		plainBuf = bytes.NewReader(append(plaintext, padding...))
	}

	iv := make([]byte, cipherBlock.BlockSize())
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("aes.Encrypt: io.ReadFull(rand.Reader, io): %w", err)
	}

	_, err = cipherBuf.Write(iv)
	if err != nil {
		return nil, fmt.Errorf("aes.Encrypt: cipherBuf.Write: %w", err)
	}

	buf := make([]byte, aes.BlockSize)

	stream := cipher.NewCTR(cipherBlock, iv)

	for {
		n, err := plainBuf.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			_, err := cipherBuf.Write(buf[:n])
			if err != nil {
				return nil, fmt.Errorf("aes.Encrypt: stream.XORKeyStream: %w", err)
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("aes.Encrypt: plainBuf.Read: %w", err)
		}
	}

	return cipherBuf.Bytes(), nil
}

func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	var plainBuf bytes.Buffer

	cipherBuf := bytes.NewReader(ciphertext)

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.Decrypt: aes.NewCipher: %w", err)
	}

	var origSize uint64
	err = binary.Read(cipherBuf, binary.LittleEndian, &origSize)
	if err != nil {
		return nil, fmt.Errorf("aes.Decrypt: binary.Read: %w", err)
	}

	iv := make([]byte, cipherBlock.BlockSize())
	if _, err := cipherBuf.Read(iv); err != nil {
		return nil, fmt.Errorf("aes.Decrypt: cipherBuf.Read: %w", err)
	}

	buf := make([]byte, aes.BlockSize)

	stream := cipher.NewCTR(cipherBlock, iv)

	for {
		n, err := cipherBuf.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			_, err := plainBuf.Write(buf[:n])
			if err != nil {
				return nil, fmt.Errorf("aes.Decrypt: plainBuf.Write: %w", err)
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf("aes.Decrypt: cipherBuf.Read: %w", err)
		}
	}

	return plainBuf.Bytes()[:origSize], nil
}
