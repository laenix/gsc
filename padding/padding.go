package padding

import (
	"bytes"
	"crypto/rand"
	"errors"
)

// PKCS#7 填充
func PKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...), nil
}

// M1 填充
func M1Padding(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	padtext := append([]byte{0x80}, bytes.Repeat([]byte{0x00}, padding-1)...)
	return append(data, padtext...), nil
}

// M1(+0) 填充
func M1PlusZeroPadding(data []byte, blockSize int) ([]byte, error) {
	// 先补一个0x80
	paddedData := append(data, 0x80)
	// 计算需要补充的0的个数
	padding := blockSize - len(paddedData)%blockSize
	if padding == blockSize {
		return paddedData, nil
	}
	// 补充0
	padtext := bytes.Repeat([]byte{0x00}, padding)
	return append(paddedData, padtext...), nil
}

// M2 填充
func M2Padding(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	if padding == blockSize {
		padding = 0
	}
	padtext := bytes.Repeat([]byte{0x00}, padding)
	return append(data, padtext...), nil
}

// ISO7816 填充
func ISO7816Padding(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	padtext[0] = 0x80
	return append(data, padtext...), nil
}

// ANSIX923 填充
func ANSIX923Padding(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	padtext[padding-1] = byte(padding)
	return append(data, padtext...), nil
}

// None 填充
func NoPadding(data []byte, blockSize int) ([]byte, error) {
	return data, nil
}

// Zero 填充
func ZeroPadding(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{0x00}, padding)
	return append(data, padtext...), nil
}

// PKCS5 填充 (PKCS#5是PKCS#7的特例，块大小固定为8字节)
func PKCS5Padding(data []byte) ([]byte, error) {
	return PKCS7Padding(data, 8)
}

// ISO10126 填充 (除最后一个字节外使用随机字节填充)
func ISO10126Padding(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	// 生成随机字节
	if _, err := rand.Read(padtext[:padding-1]); err != nil {
		return nil, err
	}
	// 最后一个字节表示填充长度
	padtext[padding-1] = byte(padding)
	return append(data, padtext...), nil
}

// TBC 填充 (Trailing Bit Complement)
func TBCPadding(data []byte, blockSize int) ([]byte, error) {
	padding := blockSize - len(data)%blockSize
	lastByte := byte(0x00)
	if len(data) > 0 {
		lastByte = data[len(data)-1]
	}
	// 使用最后一个字节的补码进行填充
	complement := ^lastByte
	padtext := bytes.Repeat([]byte{complement}, padding)
	return append(data, padtext...), nil
}

// PKCS7 解填充
func PKCS7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty data")
	}

	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding size")
	}

	return data[:(length - unpadding)], nil
}

// PKCS5 解填充
func PKCS5UnPadding(data []byte) ([]byte, error) {
	return PKCS7UnPadding(data)
}

// ISO7816 解填充
func ISO7816UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty data")
	}

	// 从后向前查找0x80
	for i := length - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i], nil
		}
		if data[i] != 0x00 {
			return nil, errors.New("invalid ISO7816 padding")
		}
	}
	return nil, errors.New("padding byte 0x80 not found")
}

// ANSIX923 解填充
func ANSIX923UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty data")
	}

	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding size")
	}

	// 验证填充字节是否都为0
	for i := length - unpadding; i < length-1; i++ {
		if data[i] != 0x00 {
			return nil, errors.New("invalid ANSI X.923 padding")
		}
	}

	return data[:(length - unpadding)], nil
}

// Zero 解填充
func ZeroUnPadding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	// 从后向前查找非零字节
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0x00 {
			return data[:(i + 1)], nil
		}
	}
	return nil, errors.New("all zero data")
}

// M1 解填充
func M1UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty data")
	}

	// 从后向前查找0x80
	for i := length - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i], nil
		}
		if data[i] != 0x00 {
			return nil, errors.New("invalid M1 padding")
		}
	}
	return nil, errors.New("padding byte 0x80 not found")
}

// M2 解填充
func M2UnPadding(data []byte) ([]byte, error) {
	return ZeroUnPadding(data)
}

// TBC 解填充
func TBCUnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("empty data")
	}

	lastByte := data[length-1]
	complement := ^lastByte

	// 验证所有填充字节是否相同
	for i := length - 1; i >= 0; i-- {
		if data[i] != complement {
			return data[:i+1], nil
		}
	}
	return nil, errors.New("invalid TBC padding")
}
