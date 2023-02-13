package encryptdir

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/prairir/encryptdir/pkg/aes"
	"github.com/prairir/encryptdir/pkg/config"
	"go.uber.org/zap"
)

func Run(log *zap.SugaredLogger, configPath string, password string, decrypt bool) error {

	_, err := Startup(configPath)
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

func Startup(configPath string) (*config.Config, error) {
	c, err := config.New(configPath)
	if err != nil {
		return nil, fmt.Errorf("encryptdir.Run: config.New: %w", err)
	}

	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("encryptdir.Run: rsa.GenerateKey: %w", err)
	}

	c.RSAKey = rsakey

	lenExtensions := len(c.Files)
	c.AESKeys, err = aes.GenKeyList(uint64(c.KeySize), lenExtensions)

	return c, nil
}
