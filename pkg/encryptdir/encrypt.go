package encryptdir

import (
	"crypto"
	gorsa "crypto/rsa"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/iafan/cwalk"
	"github.com/prairir/encryptdir/pkg/aes"
	"github.com/prairir/encryptdir/pkg/rsa"
	"go.uber.org/zap"
)

func encrypt(log *zap.SugaredLogger,
	privKey *gorsa.PrivateKey,
	keyMap map[string][]byte,
	directories []string,
) error {
	w := Walker{
		privKey: privKey,
		keyMap:  keyMap,
	}

	errC := make(chan error, 0)

	for _, dir := range directories {
		go func(dir string) { errC <- cwalk.Walk(dir, w.encryptWalk) }(dir)
	}

	// best way to handle the errors
	// loop over directories, merge errors, return if errors exist
	var errList cwalk.WalkerErrorList
	for range directories {
		err := <-errC

		var eList cwalk.WalkerErrorList
		if errors.As(err, &cwalk.WalkerErrorList{}) {
			errList.ErrorList = append(errList.ErrorList, eList.ErrorList...)
		}
	}

	if len(errList.ErrorList) > 0 {
		return fmt.Errorf("aes.Encrypt: cwalk.Walk: %s", errList.Error())
	}

	return nil
}

type Walker struct {
	privKey *gorsa.PrivateKey

	keyMap map[string][]byte
}

func (w Walker) encryptWalk(path string, info os.FileInfo, err error) error {
	if err != nil {
		return nil
	}

	errC := make(chan error, 1)
	go func(path string, info os.FileInfo, privKey *gorsa.PrivateKey, keyMap map[string][]byte, errChan chan error) {
		// dont touch dirs
		if info.IsDir() {
			errChan <- nil
			return
		}

		encFile, err := os.OpenFile(path+".enc", os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode())
		if err != nil {
			// if `.enc` file already exists, another goroutine is touching
			// the file, so move on
			if errors.Is(err, os.ErrExist) {
				errChan <- nil
				return
			}

			errChan <- fmt.Errorf("encryptdir.Walker.encryptWalk: os.OpenFile: %w", err)
			return
		}
		defer encFile.Close()

		plainFile, err := os.OpenFile(path, os.O_RDONLY, info.Mode())
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.encryptWalk: os.OpenFile: %w", err)
			return
		}
		defer plainFile.Close()

		ext := filepath.Ext(path)
		key, ok := keyMap[ext]
		// skip this file if not in key map
		if !ok {
			errChan <- nil
			return
		}

		sig := make([]byte, crypto.MD5.Size())
		_, err = plainFile.Read(sig)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.encryptWalk: plainFile.Read: %w", err)
			return
		}

		err = rsa.VerifySignature(&privKey.PublicKey, sig, key, crypto.MD5)
		if err == nil { // means signature verified and already encrypted
			errChan <- nil
			return
		}

		wSig, err := rsa.CreateSignature(privKey, key, crypto.MD5)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.encryptWalk: rsa.CreateSignature: %w", err)
			return
		}

		_, err = encFile.Write(wSig)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.encryptWalk: encFile.Write(wSig): %w", err)
			return
		}

		plain, err := io.ReadAll(plainFile)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.encryptWalk: io.ReadAll: %w", err)
			return
		}

		cipher, err := aes.Encrypt(key, plain)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.encryptWalk: aes.Encrypt: %w", err)
			return
		}

		_, err = encFile.Write(cipher)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.encryptWalk: encFile.Write: %w", err)
			return
		}

		err = os.Rename(path+".enc", path)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.encryptWalk: os.Rename: %w", err)
			return
		}

		errChan <- nil
	}(path, info, w.privKey, w.keyMap, errC)

	err = <-errC
	close(errC)
	if err != nil {
		return fmt.Errorf("encryptdir.Walker.walk: path = %q: %w", path, err)
	}
	return nil
}
