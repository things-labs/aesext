// Copyright 2020 thinkgos (thinkgo@aliyun.com).  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

// Package aesext implement block encrypt
package aesext

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
)

// New 创建一个新的加密
func New(key, salt []byte) (BlockCrypt, error) {
	bmc := BlockModeCipher{
		NewEncrypt: cipher.NewCBCEncrypter,
		NewDecrypt: cipher.NewCBCDecrypter,
	}
	newKey, iv := md5.Sum(key), md5.Sum(append(salt, key...))
	return bmc.New(newKey[:], iv[:], aes.NewCipher)
}
