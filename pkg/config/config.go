package config

import (
	"crypto/rsa"
	"fmt"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/file"
)

type Config struct {
	// FROM CONFIG FILE
	KeySize int `koanf:"key_size"`

	PublicKeyFile  string `koanf:"public_key"`
	PrivateKeyFile string `koanf:"private_key"`
	AESKeyFile     string `koanf:"aes_key"`

	Directories []string `koanf:"directories"`
	Files       []string `koanf:"files"`

	// FROM OTHER STUFF
	RSAKey  *rsa.PrivateKey
	AESKeys [][]byte
}

// config.New: load `configPath` into `config.Config`
func New(configPath string) (*Config, error) {
	k, err := Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("config.New: %w", err)
	}

	c, err := Unmarshal(k)
	if err != nil {
		return nil, fmt.Errorf("config.New: %w", err)
	}

	return c, nil
}

// config.Load: load file at `configPath` into koanf.Koanf
func Load(configPath string) (*koanf.Koanf, error) {
	k := koanf.New("/")

	err := k.Load(file.Provider(configPath), yaml.Parser())
	if err != nil {
		return nil, fmt.Errorf("config.Load: configPath = %q: %w", configPath, err)
	}
	return k, nil
}

// config.Unmarshal: unmarshal `koanf.Koanf` into `config.Config`
func Unmarshal(k *koanf.Koanf) (*Config, error) {
	var config Config
	err := k.Unmarshal("", &config)
	if err != nil {
		return nil, fmt.Errorf("config.Unmarshal: %w", err)
	}

	return &config, nil
}
