package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type SecretStore struct {
	Secrets map[string]string `json:"secrets"`
}

const (
	secretsFile = ".secretman/secrets.enc"
)

func getSecretPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(home, secretsFile)
}

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
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

func loadSecrets(key []byte) (*SecretStore, error) {
	path := getSecretPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SecretStore{Secrets: map[string]string{}}, nil
		}
		return nil, err
	}
	decrypted, err := decrypt(data, key)
	if err != nil {
		return nil, err
	}
	store := &SecretStore{}
	err = json.Unmarshal(decrypted, store)
	return store, err
}

func saveSecrets(store *SecretStore, key []byte) error {
	data, err := json.Marshal(store)
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: secretman [set|get|list|delete] key=value")
		os.Exit(1)
	}

	key := []byte(strings.Repeat("m", 32)) // In real app, derive from password
	command := os.Args[1]
	store, err := loadSecrets(key)
	if err != nil {
		panic(err)
	}

	switch command {
	case "set":
		if len(os.Args) < 3 {
			fmt.Println("Provide key=value")
			return
		}
		parts := strings.SplitN(os.Args[2], "=", 2)
		store.Secrets[parts[0]] = parts[1]
		err = saveSecrets(store, key)
	case "get":
		fmt.Println(store.Secrets[os.Args[2]])
	case "list":
		for k := range store.Secrets {
			fmt.Println(k)
		}
	case "delete":
		delete(store.Secrets, os.Args[2])
		err = saveSecrets(store, key)
	default:
		fmt.Println("Unknown command")
	}
	if err != nil {
		panic(err)
	}
}
