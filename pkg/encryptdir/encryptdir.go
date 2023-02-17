package encryptdir

import (
	gorsa "crypto/rsa"
	"errors"
	"fmt"
	"os"

	"github.com/prairir/encryptdir/pkg/aes"
	"github.com/prairir/encryptdir/pkg/config"
	"github.com/prairir/encryptdir/pkg/rsa"
	"go.uber.org/zap"
)

func Run(log *zap.SugaredLogger, configPath string, password string, decrypt bool) error {

	_, err := Startup(log, configPath, password)
	if err != nil {
		return fmt.Errorf("encryptdir.Run: encryptdir.Startup: %w", err)
	}

	log.Info("flag and config debug",
		zap.String("config path", configPath),
		zap.String("password", password),
		zap.Bool("decrypt", decrypt),
	)
	return nil
}

func Startup(log *zap.SugaredLogger, configPath string, password string) (*config.Config, error) {
	c, err := config.New(configPath)
	if err != nil {
		return nil, fmt.Errorf("encryptdir.Startup: config.New: %w", err)
	}

	rsakey, err := rsa.GetRSAKey(c.PrivateKeyFile, c.PublicKeyFile, password)
	if err != nil {
		return nil, fmt.Errorf("encryptdir.Startup: rsa.GetRSAKey: %w", err)
	}

	c.RSAKey = rsakey

	c.AESKeyMap, err = getAESKeys(log, c.RSAKey, c.AESKeyFile, uint64(c.KeySize), c.Files)
	if err != nil {
		return nil, fmt.Errorf("encryptdir.Startup: encryptdir.getAESKeys: %w", err)
	}

	// if its already written then we dont care
	err = aes.WriteKeys(c.AESKeyMap, c.RSAKey, c.AESKeyFile)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("encryptdir.Startup: aes.WriteKeys: %w", err)
	}

	log.Infof("config: %#v", c)
	return c, nil
}

// encryptdir.getAESKeys: read aes keys from file or generate em
func getAESKeys(log *zap.SugaredLogger,
	privKey *gorsa.PrivateKey,
	inPath string,
	keySize uint64,
	fileList []string) (map[string][]byte, error) {

	keyMap, err := aes.ReadKeys(privKey, inPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("encryptdir.getAESKeys: aes.ReadKeys: %w", err)
		}

		log.Info("No AES keys found, generating them...")

		keyList, err := aes.GenKeyList(keySize, len(fileList))
		if err != nil {
			return nil, fmt.Errorf("encryptdir.getAESKeys: aes.GenKeyList: %w", err)
		}

		keyMap = make(map[string][]byte)
		for n, k := range fileList {
			keyMap[k] = keyList[n]
		}
	}

	return keyMap, nil
}
