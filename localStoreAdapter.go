// Copyright © 2025 Contributors to the OpenCHAMI Project

package securestorage

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/mitchellh/mapstructure"
)

// LocalStore provides a local secret store that encrypts secrets using AES-GCM
// with a master key derived from an environment variable. It allows storing,
// retrieving, listing, and removing secrets securely in a JSON file.
// It implements the SecureStorage interface.
//

// Structure to store encrypted secrets in a JSON file
type LocalStore struct {
	mu          sync.RWMutex
	masterKey   []byte
	filename    string
	Secrets     map[string]string `json:"secrets"`
	lastModTime time.Time         // track file's last modification time
	lastSize    int64             // track file's last size
}

// Store saves a secret in the local store, encrypting it with AES-GCM
// The key is used to derive a unique AES key for each secret
// The value is expected to be a map that will be marshaled to JSON
// It reloads the contents of the file if they have changed since the last read
// If the key already exists, it will be overwritten
// If the value is nil, an error will be returned
func (l *LocalStore) Store(key string, value interface{}) error {
	if err := l.reloadIfChanged(); err != nil { // changed code
		return err
	}
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}

	// Decode the value into a map
	if value == nil {
		return fmt.Errorf("value cannot be nil")
	}
	// Use mapstructure to decode the value into a map
	var data map[string]interface{}
	err := mapstructure.Decode(value, &data)
	if err != nil {
		return err
	}
	// Convert the map to a JSON string
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal value to JSON: %v", err)
	}
	// Encrypt the JSON string using AES-GCM
	derivedKey := deriveAESKey(l.masterKey, key)
	encryptedSecret, err := encryptAESGCM(derivedKey, jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %v", err)
	}
	// Store the encrypted secret in the local store
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Secrets[key] = encryptedSecret
	err = SaveSecrets(l.filename, l.Secrets)
	return err
}

// StoreWithData is part of the SecureStorage interface and is not implemented in LocalSecretStore.
func (l *LocalStore) StoreWithData(key string, value interface{}, output interface{}) error {
	return fmt.Errorf("StoreWithData is not implemented in LocalSecretStore")
}

// Lookup retrieves a secret by its key, decrypting it with AES-GCM
func (l *LocalStore) Lookup(key string, output interface{}) error {
	if err := l.reloadIfChanged(); err != nil { // changed code
		return err
	}
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	l.mu.RLock()
	encrypted, exists := l.Secrets[key]
	l.mu.RUnlock()
	if !exists {
		return fmt.Errorf("no secret found for %s", key)
	}
	derivedKey := deriveAESKey(l.masterKey, key)
	decrypted, err := decryptAESGCM(derivedKey, encrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt secret: %v", err)
	}
	// Unmarshal the decrypted JSON string into the output interface
	err = json.Unmarshal([]byte(decrypted), output)
	if err != nil {
		return fmt.Errorf("failed to unmarshal decrypted JSON: %v", err)
	}
	return nil
}

// Delete removes a secret by its key from the local store
func (l *LocalStore) Delete(key string) error {
	if err := l.reloadIfChanged(); err != nil { // changed code
		return err
	}
	if key == "" {
		return fmt.Errorf("key cannot be empty")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// Check if the secret exists before deleting
	_, exists := l.Secrets[key]
	if !exists {
		return fmt.Errorf("no secret found for %s", key)
	}
	delete(l.Secrets, key)
	err := SaveSecrets(l.filename, l.Secrets)
	if err != nil {
		return fmt.Errorf("failed to save secrets after deletion: %v", err)
	}
	return nil
}

// LookupKeys retrieves all keys from the local store and ignores the keyPath parameter which doesn't make sense here
// It returns a slice of keys stored in the local secret store.
func (l *LocalStore) LookupKeys(keyPath string) ([]string, error) {
	if err := l.reloadIfChanged(); err != nil { // changed code
		return nil, err
	}
	if l.Secrets == nil {
		return nil, fmt.Errorf("no secrets found")
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	keys := make([]string, 0, len(l.Secrets))
	for key := range l.Secrets {
		keys = append(keys, key)
	}
	return keys, nil
}

func NewLocalSecretStore(masterKeyHex, filename string, create bool) (*LocalStore, error) {
	var secrets map[string]string

	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("unable to generate masterkey from hex representation: %v", err)
	}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		if !create {
			return nil, fmt.Errorf("file %s does not exist", filename)
		}
		file, err := os.Create(filename)
		if err != nil {
			return nil, fmt.Errorf("unable to create file %s: %v", filename, err)
		}
		file.Close()
		secrets = make(map[string]string)
	}

	if secrets == nil {
		secrets, err = loadSecrets(filename)
		if err != nil {
			return nil, fmt.Errorf("unable to load secrets from file: %v", err)
		}
	}

	lastModTime, lastSize, _ := getFileStats(filename) // file changed code (ignoring error here for brevity)

	return &LocalStore{
		masterKey:   masterKey,
		filename:    filename,
		Secrets:     secrets,
		lastModTime: lastModTime, // file changed code
		lastSize:    lastSize,
	}, nil
}

// GenerateMasterKey creates a 32-byte random key and returns it as a hex string.
func GenerateMasterKey() (string, error) {
	key := make([]byte, 32) // 32 bytes for AES-256
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// Saves secrets back to the JSON file
func SaveSecrets(jsonFile string, store map[string]string) error {
	f, err := os.OpenFile(jsonFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	// We’ll close at the end (after Sync).
	defer func() {
		_ = f.Close()
	}()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(store); err != nil {
		return err
	}
	// Ensure data is on disk…
	if err := f.Sync(); err != nil {
		return err
	}
	return nil
}

// Loads the secrets JSON file
func loadSecrets(jsonFile string) (map[string]string, error) {
	file, err := os.Open(jsonFile)
	if err != nil {
		return nil, fmt.Errorf("unable to open secret file %s:%v", jsonFile, err)
	}
	defer file.Close()

	store := make(map[string]string)
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&store)
	return store, err
}

func getFileStats(filename string) (t time.Time, size int64, err error) {
	info, err := os.Stat(filename)
	if err != nil {
		return time.Time{}, -1, err
	}
	return info.ModTime(), info.Size(), nil
}

// reloadIfChanged reloads secrets from disk if the file has been modified
func (l *LocalStore) reloadIfChanged() error {
	currentModTime, currentSize, err := getFileStats(l.filename)
	if err != nil {
		return err
	}
	if currentModTime.After(l.lastModTime) || currentSize != l.lastSize {
		secrets, err := loadSecrets(l.filename)
		if err != nil {
			return err
		}
		l.mu.Lock()
		l.Secrets = secrets
		l.lastModTime = currentModTime
		l.mu.Unlock()
	}
	return nil
}
