package padding_test

import (
	"bytes"
	"testing"

	"github.com/laenix/gsc/padding"
)

func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		want      []byte
	}{
		{
			name:      "空数据",
			data:      []byte{},
			blockSize: 8,
			want:      bytes.Repeat([]byte{8}, 8),
		},
		{
			name:      "正好一个块",
			data:      []byte("12345678"),
			blockSize: 8,
			want:      append([]byte("12345678"), bytes.Repeat([]byte{8}, 8)...),
		},
		{
			name:      "需要填充",
			data:      []byte("12345"),
			blockSize: 8,
			want:      append([]byte("12345"), bytes.Repeat([]byte{3}, 3)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := padding.PKCS7Padding(tt.data, tt.blockSize)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("PKCS7Padding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPKCS7Unpadding(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "正确填充",
			data:    append([]byte("12345"), bytes.Repeat([]byte{3}, 3)...),
			want:    []byte("12345"),
			wantErr: false,
		},
		{
			name:    "空数据",
			data:    []byte{},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "无效填充",
			data:    []byte{1, 2, 3, 4, 5, 10},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := padding.PKCS7Unpadding(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("PKCS7Unpadding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("PKCS7Unpadding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestZeroPadding(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
		want      []byte
	}{
		{
			name:      "空数据",
			data:      []byte{},
			blockSize: 8,
			want:      bytes.Repeat([]byte{0}, 8),
		},
		{
			name:      "正好一个块",
			data:      []byte("12345678"),
			blockSize: 8,
			want:      append([]byte("12345678"), bytes.Repeat([]byte{0}, 8)...),
		},
		{
			name:      "需要填充",
			data:      []byte("12345"),
			blockSize: 8,
			want:      append([]byte("12345"), bytes.Repeat([]byte{0}, 3)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := padding.ZeroPadding(tt.data, tt.blockSize)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("ZeroPadding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestZeroUnpadding(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want []byte
	}{
		{
			name: "正确填充",
			data: append([]byte("12345"), bytes.Repeat([]byte{0}, 3)...),
			want: []byte("12345"),
		},
		{
			name: "空数据",
			data: []byte{},
			want: []byte{},
		},
		{
			name: "全零数据",
			data: bytes.Repeat([]byte{0}, 8),
			want: []byte{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := padding.ZeroUnpadding(tt.data)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("ZeroUnpadding() = %v, want %v", got, tt.want)
			}
		})
	}
}
