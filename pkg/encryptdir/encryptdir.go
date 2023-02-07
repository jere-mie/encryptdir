package encryptdir

import (
	"encryptdir/pkg/config"
	"fmt"
)

func Run(configPath string) error {
	c, err := config.New(configPath)
	if err != nil {
		return fmt.Errorf("encryptdir.Run: %w", err)
	}

	fmt.Printf("hi\nconfig path: %s\nconfig: %#v", configPath, c)
	return nil
}
