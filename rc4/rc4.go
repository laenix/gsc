package rc4

import (
	"errors"
)

const (
	// 最小密钥长度（字节）
	MinKeySize = 1
	// 最大密钥长度（字节）
	MaxKeySize = 256
	// 状态数组大小
	StateSize = 256
)

// RC4 结构体定义RC4密码
type RC4 struct {
	s    [StateSize]byte // 状态数组
	i, j byte            // 状态索引
}

// 错误定义
var (
	ErrInvalidKeySize = errors.New("rc4: 密钥长度必须在1-256字节之间")
)

// New 创建一个新的RC4实例
func New(key []byte) (*RC4, error) {
	// 验证密钥长度
	if len(key) < MinKeySize || len(key) > MaxKeySize {
		return nil, ErrInvalidKeySize
	}

	// 创建RC4实例
	rc4 := &RC4{}

	// 初始化状态
	rc4.initState(key)

	return rc4, nil
}

// initState 使用密钥初始化状态数组
func (r *RC4) initState(key []byte) {
	// 初始化S盒
	for i := 0; i < StateSize; i++ {
		r.s[i] = byte(i)
	}

	// 使用密钥打乱S盒
	var j byte = 0
	for i := 0; i < StateSize; i++ {
		j = j + r.s[i] + key[i%len(key)]
		// 交换s[i]和s[j]
		r.s[i], r.s[j] = r.s[j], r.s[i]
	}

	// 初始化索引
	r.i = 0
	r.j = 0
}

// Encrypt 加密数据
func (r *RC4) Encrypt(data []byte) ([]byte, error) {
	// RC4的加密和解密是相同的
	return r.crypt(data), nil
}

// Decrypt 解密数据
func (r *RC4) Decrypt(data []byte) ([]byte, error) {
	// RC4的加密和解密是相同的
	return r.crypt(data), nil
}

// crypt 对数据进行RC4加密/解密
func (r *RC4) crypt(data []byte) []byte {
	output := make([]byte, len(data))
	copy(output, data)

	for k := 0; k < len(output); k++ {
		// 更新状态索引
		r.i = r.i + 1
		r.j = r.j + r.s[r.i]

		// 交换s[i]和s[j]
		r.s[r.i], r.s[r.j] = r.s[r.j], r.s[r.i]

		// 生成密钥流并与数据XOR
		t := r.s[r.i] + r.s[r.j]
		output[k] ^= r.s[t]
	}

	return output
}

// Reset 重置RC4状态为初始状态
func (r *RC4) Reset(key []byte) error {
	// 验证密钥长度
	if len(key) < MinKeySize || len(key) > MaxKeySize {
		return ErrInvalidKeySize
	}

	// 重新初始化状态
	r.initState(key)
	return nil
}
