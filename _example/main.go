package main

import (
	"bytes"

	"github.com/things-labs/aesext"
)

func main() {
	key, salt := []byte("iamakey"), []byte("iamasalt")

	bc, err := aesext.New(key, salt)
	if err != nil {
		panic(err)
	}
	want := []byte("iamaplaintext")

	cipherText, err := bc.Encrypt(want)
	if err != nil {
		panic(err)
	}
	got, err := bc.Decrypt(cipherText)
	if err != nil {
		panic(err)
	}

	ok := bytes.Equal(got, want)
	if !ok {
		panic("invalid encrypt and decrypt")
	}
}
