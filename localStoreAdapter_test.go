// Copyright © 2025 Contributors to the OpenCHAMI Project

package securestorage_test

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	securestorage "github.com/Cray-HPE/hms-securestorage"
)

// TestLocalStore_Store contains tests verifying the behavior of the Store method in LocalStore.
func TestLocalStore_Store(t *testing.T) {
	// This test ensures that an attempt to store with an empty key returns an error.
	t.Run("EmptyKey", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-secrets.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32) // 32 bytes for AES-256
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		err = store.Store("", map[string]interface{}{"test": "data"})
		if err == nil {
			t.Error("Expected error for empty key, got nil")
		}
	})

	// This test ensures that storing a nil value returns an error.
	t.Run("NilValue", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-secrets.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32)
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		err = store.Store("someKey", nil)
		if err == nil {
			t.Error("Expected error for nil value, got nil")
		}
	})

	// This test checks that we can store valid key-value data without errors.
	t.Run("ValidValue", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-secrets.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32)
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		err = store.Store("validKey", map[string]interface{}{"foo": "bar"})
		if err != nil {
			t.Errorf("Unexpected error storing valid key/value: %v", err)
		}
	})

	// This test verifies that the Store method triggers a file reload
	// if the underlying secrets file has changed externally.
	t.Run("ReloadIfChanged", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-secrets.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32)
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		if err := store.Store("reloadKey", map[string]interface{}{"hello": "world"}); err != nil {
			t.Fatalf("Failed to store data: %v", err)
		}

		// Simulate external change
		os.WriteFile(tmpFile, []byte(`{"reloadKey":"changedExternally"}`), 0644)

		if err := store.Store("newKey", map[string]interface{}{"another": "test"}); err != nil {
			t.Fatalf("Failed to store after external modification: %v", err)
		}
	})

	// This test demonstrates storing a custom struct that contains binary data.
	t.Run("CustomStructWithBinaryData", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-secrets-binary.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32)
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		type CustomData struct {
			ID   string
			Data []byte
		}
		input := CustomData{
			ID:   "testID",
			Data: []byte{0x00, 0x01, 0x02, 0x03},
		}

		err = store.Store("binaryKey", input)
		if err != nil {
			t.Fatalf("Failed to store custom struct with binary data: %v", err)
		}

		var output CustomData
		if err := store.Lookup("binaryKey", &output); err != nil {
			t.Fatalf("Failed to retrieve custom struct with binary data: %v", err)
		}
		if output.ID != input.ID {
			t.Errorf("Expected ID to be %q, got %q", input.ID, output.ID)
		}
		if !bytes.Equal(output.Data, input.Data) {
			t.Error("Binary data mismatch between stored and retrieved values")
		}
	})
}

// TestLocalStore_Lookup contains tests verifying the behavior of the Lookup method in LocalStore.
func TestLocalStore_Lookup(t *testing.T) {
	// This test ensures that an attempt to look up with an empty key returns an error.
	t.Run("EmptyKey", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-lookup-secrets.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32)
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		var output map[string]interface{}
		err = store.Lookup("", &output)
		if err == nil {
			t.Error("Expected error for empty key, got nil")
		}
	})

	// This test ensures that looking up a non-existent key returns an error.
	t.Run("KeyNotFound", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-lookup-secrets.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32)
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		var output map[string]interface{}
		err = store.Lookup("notFoundKey", &output)
		if err == nil {
			t.Error("Expected error for non-existent key, got nil")
		}
	})

	// This test checks that a key that exists can be looked up successfully.
	t.Run("ValidLookup", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-lookup-secrets.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32)
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		// Store a valid key before trying to look it up
		if err := store.Store("lookupKey", map[string]interface{}{"foo": "bar"}); err != nil {
			t.Fatalf("Failed to store data for lookup test: %v", err)
		}

		var output map[string]interface{}
		if err := store.Lookup("lookupKey", &output); err != nil {
			t.Fatalf("Failed to look up valid key: %v", err)
		}
		if val, ok := output["foo"]; !ok || val != "bar" {
			t.Errorf("Expected 'foo' to be 'bar', got %v", val)
		}
	})

	// This test verifies that the Lookup method triggers a file reload
	// if the underlying secrets file has changed externally, and that
	// the changed contents are visible after reloading.
	t.Run("ReloadIfChanged", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-lookup-secrets.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32)
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		// Store data initially
		if err := store.Store("reloadLookupKey", map[string]interface{}{"hello": "world"}); err != nil {
			t.Fatalf("Failed to store data: %v", err)
		}

		// Simulate external change - note the updated JSON, changing the structure to a plain string
		os.WriteFile(tmpFile, []byte(`{"reloadLookupKey":"changedExternally"}`), 0644)

		// Lookup should detect external change and reload before reading.
		// We'll use an empty interface to reflect the new type in the file (a string).
		var output interface{}
		if err := store.Lookup("reloadLookupKey", &output); err == nil {
			t.Fatalf("Failed to fail while looking up an unencrypted key after an out of band write of the file: %v", err)
		}
	})

	// This test demonstrates looking up a custom struct that contains binary data.
	t.Run("CustomStructWithBinaryData", func(t *testing.T) {
		tmpFile := filepath.Join(os.TempDir(), "test-lookup-secrets-binary.json")
		defer os.Remove(tmpFile)

		masterKey := make([]byte, 32)
		masterKeyHex := hex.EncodeToString(masterKey)
		store, err := securestorage.NewLocalSecretStore(masterKeyHex, tmpFile, true)
		if err != nil {
			t.Fatalf("Failed to create LocalStore: %v", err)
		}

		type CustomData struct {
			ID   string
			Data []byte
		}
		input := CustomData{
			ID:   "binaryTestID",
			Data: []byte{0x45, 0x46, 0x47, 0x48},
		}

		// Store the custom struct
		if err := store.Store("binaryLookupKey", input); err != nil {
			t.Fatalf("Failed to store custom struct: %v", err)
		}

		// Lookup the custom struct
		var output CustomData
		if err := store.Lookup("binaryLookupKey", &output); err != nil {
			t.Fatalf("Failed to lookup custom struct: %v", err)
		}
		if output.ID != input.ID {
			t.Errorf("Expected ID to be %q, got %q", input.ID, output.ID)
		}
		if !bytes.Equal(output.Data, input.Data) {
			t.Error("Binary data mismatch between stored and retrieved values")
		}
	})
}
