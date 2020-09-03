// Copyright 2020 thinkgos (thinkgo@aliyun.com).  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aesext

import (
	"bytes"
	"crypto/cipher"
	"errors"
)

// error defined
var (
	ErrInputNotMultipleBlocks = errors.New("decoded message length must be multiple of block size")
	ErrInvalidIvSize          = errors.New("iv length must equal block size")
	ErrUnPaddingOutOfRange    = errors.New("unPadding out of range")
)

// BlockCrypt block crypt interface
type BlockCrypt interface {
	// BlockSize returns the mode's block size.
	BlockSize() int
	// Encrypt plain text. return cipher text, not contains iv.
	Encrypt(plainText []byte) ([]byte, error)
	// Encrypt cipher text cipher text. plain text, not contains iv.
	Decrypt(cipherText []byte) ([]byte, error)
}

// BlockModeCipher block mode cipher
// support:
//      cbc: cipher.NewCBCEncrypter, cipher.NewCBCDecrypter
type BlockModeCipher struct {
	NewEncrypt func(block cipher.Block, iv []byte) cipher.BlockMode
	NewDecrypt func(block cipher.Block, iv []byte) cipher.BlockMode
}

// New new with newCipher and key, iv
// newCipher support follow or implement func(key []byte) (cipher.Block, error):
// 		aes
// 		cipher
// 		des
// 		blowfish
// 		cast5
// 		twofish
// 		xtea
// 		tea
func (sf *BlockModeCipher) New(key, iv []byte, newCipher func(key []byte) (cipher.Block, error)) (BlockCrypt, error) {
	block, err := newCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, ErrInvalidIvSize
	}
	bb := &blockBlock{
		block:      block,
		iv:         iv,
		newEncrypt: sf.NewEncrypt,
		newDecrypt: sf.NewDecrypt,
	}
	return bb, nil
}

type blockBlock struct {
	block      cipher.Block
	iv         []byte
	newEncrypt func(block cipher.Block, iv []byte) cipher.BlockMode
	newDecrypt func(block cipher.Block, iv []byte) cipher.BlockMode
}

func (sf *blockBlock) BlockSize() int {
	return sf.block.BlockSize()
}

// Encrypt encrypt
func (sf *blockBlock) Encrypt(plainText []byte) ([]byte, error) {
	orig := PCKSPadding(plainText, sf.block.BlockSize())
	sf.newEncrypt(sf.block, sf.iv).CryptBlocks(orig, orig)
	return orig, nil
}

// Decrypt decrypt
func (sf *blockBlock) Decrypt(cipherText []byte) ([]byte, error) {
	blockSize := sf.block.BlockSize()
	if len(cipherText) == 0 || len(cipherText)%blockSize != 0 {
		return nil, ErrInputNotMultipleBlocks
	}
	cipher.NewCBCDecrypter(sf.block, sf.iv).CryptBlocks(cipherText, cipherText)
	return PCKSUnPadding(cipherText)
}

// PCKSPadding PKCS#5和PKCS#7 填充
func PCKSPadding(origData []byte, blockSize int) []byte {
	padSize := blockSize - len(origData)%blockSize
	padText := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(origData, padText...)
}

// PCKSUnPadding PKCS#5和PKCS#7 解填充
func PCKSUnPadding(origData []byte) ([]byte, error) {
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
