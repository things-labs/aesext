// Package aesExt imp AES-128 CBC PCKS7 Padding with your salt
// PKCS#5 padding is identical to PKCS#7 padding, PCKS5 use for 64bit padding
package aesExt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"errors"
)

// ErrInputNotFullBlocks input not full blocks
var ErrInputNotFullBlocks = errors.New("input not full blocks")

// ErrUnPaddingOutOfRange unPadding out of range
var ErrUnPaddingOutOfRange = errors.New("unPadding out of range")

// Secret 加密
type Secret struct {
	key  []byte
	salt []byte
}

// New 创建一个新的加密
func New(key, salt []byte) Secret {
	return Secret{key, salt}
}

// PKCS#5和PKCS#7 填充
func pcksPadding(origData []byte, size int) []byte {
	padSize := size - len(origData)%size
	return append(origData, bytes.Repeat([]byte{byte(padSize)}, padSize)...)
}

// PKCS#5和PKCS#7 解填充
func pcksUnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, ErrUnPaddingOutOfRange
	}
	unPadSize := int(origData[length-1])
	if unPadSize > length {
		return nil, ErrUnPaddingOutOfRange
	}
	return origData[:(length - unPadSize)], nil
}

// Encrypt 加密
func (sf Secret) Encrypt(text []byte) ([]byte, error) {
	newKey, iv := md5.Sum(sf.key), md5.Sum(append(sf.salt, sf.key...))

	block, err := aes.NewCipher(newKey[:])
	if err != nil {
		return nil, err
	}
	msg := pcksPadding(text, block.BlockSize())
	cipher.
		NewCBCEncrypter(block, iv[:]).
		CryptBlocks(msg, msg)
	return msg, nil
}

// Decrypt 解密
func (sf Secret) Decrypt(text []byte) ([]byte, error) {
	newKey, iv := md5.Sum(sf.key), md5.Sum(append(sf.salt, sf.key...))

	block, err := aes.NewCipher(newKey[:])
	if err != nil {
		return nil, err
	}
	if len(text) == 0 || len(text)%block.BlockSize() != 0 {
		return nil, ErrInputNotFullBlocks
	}
	cipher.
		NewCBCDecrypter(block, iv[:]).
		CryptBlocks(text, text)
	return pcksUnPadding(text)
}
