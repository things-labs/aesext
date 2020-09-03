package aesext

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var aesKeySizes = []int{16, 24, 32}

func mockErrorNewCipher([]byte) (cipher.Block, error) {
	return nil, errors.New("mock error new cipher")
}

func TestBlockModeCipher(t *testing.T) {
	key := []byte("secret_key")
	salt := []byte("secret_salt")
	newKey, iv := sha256.Sum256(key), sha256.Sum256(append(salt, key...))

	t.Run("aes", func(t *testing.T) {
		plainText := []byte("helloworld,this is golang language. welcome")
		for _, keySize := range aesKeySizes {
			bc := BlockModeCipher{
				cipher.NewCBCEncrypter,
				cipher.NewCBCDecrypter,
			}
			blk, err := bc.New(newKey[:keySize], iv[:aes.BlockSize], aes.NewCipher)
			require.NoError(t, err)

			assert.Equal(t, aes.BlockSize, blk.BlockSize())

			cipherText, err := blk.Encrypt(plainText)
			require.NoError(t, err)
			want, err := blk.Decrypt(cipherText)
			require.NoError(t, err)
			assert.Equal(t, want, plainText)

			cipherText, err = blk.Encrypt(plainText)
			require.NoError(t, err)
			want, err = blk.Decrypt(cipherText)
			require.NoError(t, err)
			assert.Equal(t, want, plainText)
		}
	})

	t.Run("invalid iv length", func(t *testing.T) {
		bc := BlockModeCipher{
			cipher.NewCBCEncrypter,
			cipher.NewCBCDecrypter,
		}
		_, err := bc.New(newKey[:16], []byte{}, aes.NewCipher)
		require.Error(t, err)
	})
	t.Run("invalid cipher", func(t *testing.T) {
		bc := BlockModeCipher{
			cipher.NewCBCEncrypter,
			cipher.NewCBCDecrypter,
		}
		_, err := bc.New(newKey[:16], iv[:aes.BlockSize], mockErrorNewCipher)
		require.Error(t, err)
	})
}
