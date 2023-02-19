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

func decryptDirectories(log *zap.SugaredLogger,
	privKey *gorsa.PrivateKey, keyMap map[string][]byte,
	directories []string,
) error {

	errC := make(chan error, 0)

	for _, dir := range directories {
		w := Walker{
			privKey:   privKey,
			keyMap:    keyMap,
			startPath: dir,
		}
		go func(dir string) { errC <- cwalk.Walk(dir, w.decryptWalk) }(dir)
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

func (w Walker) decryptWalk(path string, info os.FileInfo, err error) error {
	if err != nil {
		return nil
	}

	errC := make(chan error, 1)

	go func(startPath string, path string, info os.FileInfo, privKey *gorsa.PrivateKey, keyMap map[string][]byte, errChan chan error) {
		if info.IsDir() { // skip dirs
			errChan <- nil
			return
		}

		ext := filepath.Ext(path)
		key, ok := keyMap[ext[1:]]

		// skip this file if not in key map
		if !ok {
			errChan <- nil
			return
		}

		fullPath := filepath.Join(startPath, path)

		cipherFile, err := os.OpenFile(fullPath, os.O_RDONLY, info.Mode())
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.decryptWalk: os.OpenFile: %w", err)
			return
		}
		defer cipherFile.Close()

		sig := make([]byte, aes.SIGNATURE_SIZE)
		_, err = cipherFile.Read(sig)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.decryptWalk: cipherFile.Read: %w", err)
			return
		}

		err = rsa.VerifySignature(&privKey.PublicKey, sig, key, crypto.MD5)
		if err != nil { // means signature isnt valid, meaning decrypted
			errChan <- nil
			return
		}

		cipher, err := io.ReadAll(cipherFile)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.decryptWalk: io.ReadAll: %w", err)
			return
		}

		plain, err := aes.Decrypt(key, cipher)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.decryptWalk: aes.Decrypt: %w", err)
			return
		}

		decFile, err := os.OpenFile(fullPath+".dec", os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode())
		if err != nil {
			// if `.dec` file already exists, another goroutine is touchine
			// so move on
			if errors.Is(err, os.ErrExist) {
				errChan <- nil
				return
			}

			errChan <- fmt.Errorf("encryptdir.Walker.decryptWalk: os.OpenFile: %w", err)
			return
		}
		defer decFile.Close()

		_, err = decFile.Write(plain)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.decryptWalk:  decFile.Write: %w", err)
			return
		}

		err = os.Rename(fullPath+".dec", fullPath)
		if err != nil {
			errChan <- fmt.Errorf("encryptdir.Walker.decryptWalk:  os.Rename: %w", err)
			return
		}

		errChan <- nil
	}(w.startPath, path, info, w.privKey, w.keyMap, errC)

	err = <-errC
	close(errC)
	if err != nil {
		return fmt.Errorf("encryptdir.Walker.walk: path = %q: %w", path, err)
	}
	return nil
}
