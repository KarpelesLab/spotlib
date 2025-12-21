package spotlib

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BottleFmt/gobottle"
)

// ClientData is an interface for providing client identity data including cryptographic keys.
// Implementations should return a keychain containing at least one private key for signing.
type ClientData interface {
	// Keychain returns a keychain with at least one private key for client identity
	Keychain() *gobottle.Keychain
}

// diskStore implements ClientData and persists keys to disk in the user's config directory.
// Keys are stored in PEM-encoded PKCS#8 format as id_<key_type>.key files.
type diskStore struct {
	path string
	kc   *gobottle.Keychain
}

// NewDiskStore creates a new disk-based store for client data.
// Data is stored in filepath.Join(os.UserConfigDir(), "spot").
// If no keys exist, a new ECDSA P-256 key is generated automatically.
func NewDiskStore() (*diskStore, error) {
	return NewDiskStoreWithPath("")
}

// NewDiskStoreWithPath creates a new disk-based store at the specified path.
// If path is empty, it defaults to filepath.Join(os.UserConfigDir(), "spot").
// If no keys exist, a new ECDSA P-256 key is generated automatically.
func NewDiskStoreWithPath(path string) (*diskStore, error) {
	if path == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user config directory: %w", err)
		}
		path = filepath.Join(configDir, "spot")
	}

	// Ensure directory exists
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, fmt.Errorf("failed to create store directory: %w", err)
	}

	ds := &diskStore{
		path: path,
		kc:   gobottle.NewKeychain(),
	}

	// Load existing keys
	if err := ds.loadKeys(); err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	// If no keys exist, generate a new one
	hasKeys := false
	ds.kc.All(func(k gobottle.PrivateKey) bool {
		hasKeys = true
		return false
	})

	if !hasKeys {
		if err := ds.generateKey(); err != nil {
			return nil, fmt.Errorf("failed to generate initial key: %w", err)
		}
	}

	return ds, nil
}

// Keychain returns the keychain containing the client's private keys.
func (ds *diskStore) Keychain() *gobottle.Keychain {
	return ds.kc
}

// Path returns the directory path where keys are stored.
func (ds *diskStore) Path() string {
	return ds.path
}

// loadKeys loads all key files from the store directory.
func (ds *diskStore) loadKeys() error {
	entries, err := os.ReadDir(ds.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "id_") || !strings.HasSuffix(name, ".key") {
			continue
		}

		keyPath := filepath.Join(ds.path, name)
		if err := ds.loadKeyFile(keyPath); err != nil {
			// Log but continue loading other keys
			continue
		}
	}

	return nil
}

// loadKeyFile loads a single PEM-encoded PKCS#8 private key file.
func (ds *diskStore) loadKeyFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return fmt.Errorf("unexpected PEM type: %s", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	return ds.kc.AddKey(key)
}

// generateKey generates a new ECDSA P-256 private key and saves it to disk.
func (ds *diskStore) generateKey() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	if err := ds.saveKey(key, "ecdsa"); err != nil {
		return err
	}

	return ds.kc.AddKey(key)
}

// AddKey adds a private key to the keychain and saves it to disk.
// The keyType should describe the key (e.g., "ecdsa", "rsa", "ed25519").
func (ds *diskStore) AddKey(key any, keyType string) error {
	if err := ds.saveKey(key, keyType); err != nil {
		return err
	}
	return ds.kc.AddKey(key)
}

// saveKey saves a private key to disk in PEM-encoded PKCS#8 format.
func (ds *diskStore) saveKey(key any, keyType string) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	filename := fmt.Sprintf("id_%s.key", keyType)
	path := filepath.Join(ds.path, filename)

	// Check if file already exists, add suffix if needed
	if _, err := os.Stat(path); err == nil {
		// File exists, find a unique name
		for i := 1; ; i++ {
			filename = fmt.Sprintf("id_%s_%d.key", keyType, i)
			path = filepath.Join(ds.path, filename)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				break
			}
		}
	}

	// Write with restricted permissions (owner read/write only)
	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}
