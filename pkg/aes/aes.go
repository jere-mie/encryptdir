package aes

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// aes.GenKeyList: Generates a list of random keys of random size
func GenKeyList(length int) ([][]byte, error) {
	keyList := make([][]byte, length)

	for i := 0; i < len(keyList); i++ {
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
		keySize := (128 + (64 * n64))

		keyList[i] = make([]byte, keySize)

		keyList[i], err = GenKey(uint(keySize))
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
