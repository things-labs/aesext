## aesext 
    
这是一个块加密,固定Key固定IV,加解密长度一致,不传IV.所以同一白文加密后,密文是一致的.  
如需密文传输随机IV,请使用 [encrypt](https://github.com/things-go/encrypt) 的encrypt的块加密

[![GoDoc](https://godoc.org/github.com/things-labs/aesext?status.svg)](https://godoc.org/github.com/things-labs/aesext)
[![Go.Dev reference](https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white)](https://pkg.go.dev/github.com/things-labs/aesext?tab=doc)
[![Build Status](https://travis-ci.com/things-labs/aesext.svg?branch=master)](https://travis-ci.com/things-labs/aesext)
[![codecov](https://codecov.io/gh/things-labs/aesext/branch/master/graph/badge.svg)](https://codecov.io/gh/things-labs/aesext)
![Action Status](https://github.com/things-labs/aesext/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/things-labs/aesext)](https://goreportcard.com/report/github.com/things-labs/aesext)
[![Licence](https://img.shields.io/github/license/things-labs/aesext)](https://github.com/things-labs/aesext/raw/master/LICENSE)
[![Tag](https://img.shields.io/github/v/tag/things-labs/aesext)](https://github.com/things-labs/aesext/tags)


```bash
    go get github.com/things-labs/aesext
```

## Import:

```go
    import "github.com/things-labs/aesext"
```

## Example

[embedmd]:# (_example/main.go go)
```go
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
```



## License

This project is under MIT License. See the [LICENSE](LICENSE) file for the full license text.
