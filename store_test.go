package spotlib_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/BottleFmt/gobottle"
	"github.com/KarpelesLab/spotlib"
)

func TestNewDiskStore(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "spotlib-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "spot")

	// Create a new store - should generate a key
	store, err := spotlib.NewDiskStoreWithPath(storePath)
	if err != nil {
		t.Fatalf("NewDiskStoreWithPath failed: %v", err)
	}

	// Verify keychain has at least one key
	kc := store.Keychain()
	if kc == nil {
		t.Fatal("Keychain() returned nil")
	}

	signer := kc.FirstSigner()
	if signer == nil {
		t.Fatal("Keychain has no signers")
	}

	// Verify key file was created
	files, err := os.ReadDir(storePath)
	if err != nil {
		t.Fatalf("failed to read store dir: %v", err)
	}

	foundKey := false
	for _, f := range files {
		if f.Name() == "id_ecdsa.key" {
			foundKey = true
			break
		}
	}
	if !foundKey {
		t.Error("id_ecdsa.key not found in store directory")
	}

	// Create another store at the same path - should load existing key
	store2, err := spotlib.NewDiskStoreWithPath(storePath)
	if err != nil {
		t.Fatalf("second NewDiskStoreWithPath failed: %v", err)
	}

	signer2 := store2.Keychain().FirstSigner()
	if signer2 == nil {
		t.Fatal("second store has no signers")
	}

	// Verify it's the same key (compare public keys)
	pub1, ok1 := signer.Public().(*ecdsa.PublicKey)
	pub2, ok2 := signer2.Public().(*ecdsa.PublicKey)
	if !ok1 || !ok2 {
		t.Fatal("expected ECDSA public keys")
	}

	if !pub1.Equal(pub2) {
		t.Error("loaded key does not match original key")
	}
}

func TestDiskStoreAddKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "spotlib-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "spot")

	store, err := spotlib.NewDiskStoreWithPath(storePath)
	if err != nil {
		t.Fatalf("NewDiskStoreWithPath failed: %v", err)
	}

	// Generate a second key and add it
	key2, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}

	err = store.AddKey(key2, "ecdsa")
	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}

	// Verify both keys are in the keychain
	keyCount := 0
	store.Keychain().All(func(k gobottle.PrivateKey) bool {
		keyCount++
		return true
	})

	if keyCount != 2 {
		t.Errorf("expected 2 keys, got %d", keyCount)
	}

	// Verify second key file was created with unique name
	files, err := os.ReadDir(storePath)
	if err != nil {
		t.Fatalf("failed to read store dir: %v", err)
	}

	keyFiles := 0
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".key" {
			keyFiles++
		}
	}

	if keyFiles != 2 {
		t.Errorf("expected 2 key files, got %d", keyFiles)
	}
}

func TestDiskStorePath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "spotlib-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "spot")

	store, err := spotlib.NewDiskStoreWithPath(storePath)
	if err != nil {
		t.Fatalf("NewDiskStoreWithPath failed: %v", err)
	}

	if store.Path() != storePath {
		t.Errorf("Path() = %q, want %q", store.Path(), storePath)
	}
}

func TestClientDataInterface(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "spotlib-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	storePath := filepath.Join(tmpDir, "spot")

	store, err := spotlib.NewDiskStoreWithPath(storePath)
	if err != nil {
		t.Fatalf("NewDiskStoreWithPath failed: %v", err)
	}

	// Verify diskStore implements ClientData interface
	var _ spotlib.ClientData = store
}
