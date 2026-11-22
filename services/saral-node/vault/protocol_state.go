package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// SaveProtocolState records a wallet DKG checkpoint under the node's vault key.
// The checkpoint must be durable before the node sends a new authenticated vote.
func (s *ShareStore) SaveProtocolState(scope, kind string, state []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, aad, aead, err := s.protocolState(scope, kind)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	encrypted := aead.Seal(nonce, nonce, state, aad)
	return s.writeDurableState(path, encrypted)
}

func (s *ShareStore) writeDurableState(path string, encrypted []byte) error {
	file, err := os.CreateTemp(s.vaultDir, ".protocol-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(encrypted)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return s.syncProtocolDirectory()
}

func (s *ShareStore) DeleteProtocolState(scope, kind string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, _, _, err := s.protocolState(scope, kind)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.syncProtocolDirectory()
}

func (s *ShareStore) syncProtocolDirectory() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(s.vaultDir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s *ShareStore) LoadProtocolState(scope, kind string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	path, aad, aead, err := s.protocolState(scope, kind)
	if err != nil {
		return nil, err
	}
	encrypted, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	size := aead.NonceSize()
	if len(encrypted) < size+aead.Overhead() {
		return nil, fmt.Errorf("truncated DKG checkpoint")
	}
	return aead.Open(nil, encrypted[:size], encrypted[size:], aad)
}

func (s *ShareStore) protocolState(scope, kind string) (string, []byte, cipher.AEAD, error) {
	if !s.Persistent() || !ValidRecordID(scope) || !ValidRecordID(kind) {
		return "", nil, nil, fmt.Errorf("invalid protocol checkpoint location")
	}
	aad := []byte("saral/vault/dkg-checkpoint/v1/" + scope + "/" + kind)
	digest := sha256.Sum256(aad)
	name := "protocol_" + hex.EncodeToString(digest[:]) + ".bin"
	block, err := aes.NewCipher(s.vaultKey)
	if err != nil {
		return "", nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, nil, err
	}
	return filepath.Join(s.vaultDir, name), aad, aead, nil
}
