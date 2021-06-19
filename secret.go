// Copyright 2020 thinkgos (thinkgo@aliyun.com).  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

// Package aesext implement block encrypt
package aesext

import (
	"crypto/aes"
	"crypto/md5"
)

// New 创建一个新的加密
// aes-128加密
// support:
//      cbc(default): cipher.NewCBCEncrypter, cipher.NewCBCDecrypter
func New(key, salt []byte, opts ...Option) (BlockCrypt, error) {
	newKey, iv := md5.Sum(key), md5.Sum(append(salt, key...))
	return NewBlockCrypt(newKey[:], iv[:], aes.NewCipher, opts...)
}
