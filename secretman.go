package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"golang.org/x/crypto/scrypt"
	"os"
	"path/filepath"
)

// SecretStore holds encrypted secrets and a key
type SecretStore struct {
	secrets map[string]string
	key     []byte
}

const (
	secretsFile = ".secretman/secrets.enc"
	saltFile    = ".secretman/salt"
)

// Get the path for the secrets file
func getSecretPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(home, secretsFile)
}

// Get the path for the salt file
func getSaltPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(home, saltFile)
}

// Derive the encryption key from the password using scrypt
func deriveKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
}

// Create or load the salt file
func getOrCreateSalt() ([]byte, error) {
	path := getSaltPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		err := os.MkdirAll(filepath.Dir(path), 0700)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, salt, 0600); err != nil {
			return nil, err
		}
		return salt, nil
	}
	return os.ReadFile(path)
}

// Encrypt data with the provided key
func encrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt data with the provided key
func decrypt(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("data too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// Load secrets from the encrypted file
func loadSecrets(key []byte) (map[string]string, error) {
	path := getSecretPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	decrypted, err := decrypt(data, key)
	if err != nil {
		return nil, err
	}
	secrets := map[string]string{}
	err = json.Unmarshal(decrypted, &secrets)
	return secrets, err
}

// Save secrets to the encrypted file
func saveSecrets(secrets map[string]string, key []byte) error {
	data, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	encrypted, err := encrypt(data, key)
	if err != nil {
		return err
	}
	path := getSecretPath()
	err = os.MkdirAll(filepath.Dir(path), 0700)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encrypted, 0600)
}

// Initialize the store with the password
func Init(password string) (*SecretStore, error) {
	salt, err := getOrCreateSalt()
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	secrets, err := loadSecrets(key)
	if err != nil {
		return nil, err
	}
	return &SecretStore{secrets: secrets, key: key}, nil
}

// Get a secret by key
func (s *SecretStore) Get(key string) string {
	return s.secrets[key]
}

// Set a secret with a key-value pair
func (s *SecretStore) Set(key, value string) error {
	s.secrets[key] = value
	return saveSecrets(s.secrets, s.key)
}

// Delete a secret by key
func (s *SecretStore) Delete(key string) error {
	delete(s.secrets, key)
	return saveSecrets(s.secrets, s.key)
}

// List all secret keys
func (s *SecretStore) ListKeys() []string {
	keys := make([]string, 0, len(s.secrets))
	for k := range s.secrets {
		keys = append(keys, k)
	}
	return keys
}

// Export secrets as JSON
func (s *SecretStore) AsJSON() (string, error) {
	b, err := json.MarshalIndent(s.secrets, "", "  ")
	return string(b), err
}
