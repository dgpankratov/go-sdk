package solidgate

import (
	"bytes"
	"testing"
)

func TestPkcs7Pad(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		wantErr   bool
	}{
		{
			name:      "valid padding",
			data:      []byte("test"),
			blockSize: 8,
			wantErr:   false,
		},
		{
			name:      "empty data",
			data:      []byte{},
			blockSize: 8,
			wantErr:   true,
		},
		{
			name:      "invalid block size",
			data:      []byte("test"),
			blockSize: 0,
			wantErr:   true,
		},
		{
			name:      "exact block size",
			data:      []byte("12345678"),
			blockSize: 8,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := pkcs7Pad(tt.data, tt.blockSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("pkcs7Pad() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(result)%tt.blockSize != 0 {
					t.Errorf("padded data length %d is not multiple of block size %d", len(result), tt.blockSize)
				}
				if len(result) < len(tt.data) {
					t.Errorf("padded data length %d is less than original data length %d", len(result), len(tt.data))
				}
			}
		})
	}
}

func TestEncryptCBC(t *testing.T) {
	validKey := []byte("12345678901234567890123456789012") // 32 bytes
	invalidKey := []byte("short-key")

	tests := []struct {
		name    string
		key     []byte
		data    []byte
		wantErr bool
	}{
		{
			name:    "valid encryption",
			key:     validKey,
			data:    []byte("test data"),
			wantErr: false,
		},
		{
			name:    "empty data",
			key:     validKey,
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "invalid key length",
			key:     invalidKey,
			data:    []byte("test data"),
			wantErr: true,
		},
		{
			name:    "long data",
			key:     validKey,
			data:    []byte("this is a longer test data that needs to be encrypted and should be properly padded"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := EncryptCBC(tt.key, tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptCBC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(result) <= len(tt.data) {
					t.Errorf("encrypted data length %d is not greater than original data length %d", len(result), len(tt.data))
				}
				if len(result) < 16 { // AES block size
					t.Errorf("encrypted data length %d is less than AES block size", len(result))
				}
			}
		})
	}
}

func TestEncryptCBC_Consistency(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	data := []byte("test data")

	// Encrypt the same data twice
	result1, err1 := EncryptCBC(key, data)
	if err1 != nil {
		t.Fatalf("First encryption failed: %v", err1)
	}

	result2, err2 := EncryptCBC(key, data)
	if err2 != nil {
		t.Fatalf("Second encryption failed: %v", err2)
	}

	// Results should be different due to random IV
	if bytes.Equal(result1, result2) {
		t.Error("EncryptCBC() produced identical results for same input")
	}
}
