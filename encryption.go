package solidgate

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrInvalidBlockSize is returned when the block size is invalid
	ErrInvalidBlockSize = errors.New("block size must be greater than 0")

	// ErrEmptyData is returned when the data to encrypt is empty
	ErrEmptyData = errors.New("data to encrypt cannot be empty")

	// ErrInvalidKeySize is returned when the key size is invalid
	ErrInvalidKeySize = errors.New("key size must be 32 bytes")
)

// pkcs7Pad pads the data according to PKCS#7 standard
func pkcs7Pad(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, fmt.Errorf("pkcs7pad: %w", ErrInvalidBlockSize)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("pkcs7pad: %w", ErrEmptyData)
	}

	padding := blockSize - (len(data) % blockSize)
	paddedData := make([]byte, len(data)+padding)

	copy(paddedData, data)
	copy(paddedData[len(data):], bytes.Repeat([]byte{byte(padding)}, padding))

	return paddedData, nil
}

// EncryptCBC encrypts data using AES-CBC mode with PKCS#7 padding
// key must be 32 bytes long
func EncryptCBC(key, data []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encrypt: %w", ErrInvalidKeySize)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("encrypt: %w", ErrEmptyData)
	}

	// Pad the data
	paddedData, err := pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("encrypt: create cipher: %w", err)
	}

	// Create ciphertext buffer with space for IV
	ciphertext := make([]byte, aes.BlockSize+len(paddedData))

	// Generate random IV
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("encrypt: generate IV: %w", err)
	}

	// Create CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	// Encrypt the data
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedData)

	return ciphertext, nil
}
