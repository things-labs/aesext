package aesext

import (
	"reflect"
	"testing"
)

func TestSecret_Encrypt(t *testing.T) {
	type fields struct {
		key  []byte
		salt []byte
	}
	type args struct {
		origData []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"test key and salt a",
			fields{
				[]byte("test"),
				[]byte("a")},
			args{
				[]byte("test")},
			[]byte{0xce, 0xa2, 0x2a, 0x28, 0xaa, 0x9f, 0xef, 0x87,
				0x09, 0xe2, 0x5d, 0xda, 0xf8, 0xc6, 0xc0, 0xe5},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			this := New(tt.fields.key, tt.fields.salt)
			got, err := this.Encrypt(tt.args.origData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Secret.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Secret.Encrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSecret_Decrypt(t *testing.T) {
	type fields struct {
		key  []byte
		salt []byte
	}
	type args struct {
		orgiData []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			"test key and salt a",
			fields{
				[]byte("test"),
				[]byte("a")},
			args{
				[]byte{0xce, 0xa2, 0x2a, 0x28, 0xaa, 0x9f, 0xef, 0x87,
					0x09, 0xe2, 0x5d, 0xda, 0xf8, 0xc6, 0xc0, 0xe5},
			},
			[]byte("test"),
			false,
		},
		{
			"input not full blocks",
			fields{
				[]byte("test"),
				[]byte("a"),
			},
			args{

				[]byte{0xce},
			},
			nil,
			true,
		},
		{
			"invalid",
			fields{[]byte("test"), []byte("a")},
			args{
				[]byte{0xce, 0xa2, 0x2a, 0x28, 0xaa, 0x9f, 0xef, 0x87,
					0x09, 0xe2, 0x5d, 0xda, 0xf8, 0xc6, 0xc0, 0xf5},
			},
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			this := &Secret{
				key:  tt.fields.key,
				salt: tt.fields.salt,
			}
			got, err := this.Decrypt(tt.args.orgiData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Secret.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Secret.Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
