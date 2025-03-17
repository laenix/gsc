package modes

import "errors"

// 常见错误
var (
	ErrInvalidBlockSize = errors.New("无效的块大小")
	ErrInvalidDataSize  = errors.New("数据长度必须是块大小的整数倍")
	ErrInvalidPadding   = errors.New("无效的填充")
	ErrInvalidIV        = errors.New("无效的初始化向量")
	ErrInvalidNonce     = errors.New("无效的nonce")
	ErrDataTooLarge     = errors.New("数据长度超过限制")
	ErrTagMismatch      = errors.New("认证标签不匹配")
)

// BlockCipher 接口定义块加密算法应实现的方法
type BlockCipher interface {
	// Encrypt 加密单个块
	Encrypt([]byte) ([]byte, error)
	// Decrypt 解密单个块
	Decrypt([]byte) ([]byte, error)
	// BlockSize 返回块大小（字节）
	BlockSize() int
}

// Mode 接口定义了所有块加密模式共有的方法
type Mode interface {
	// Encrypt 加密数据
	Encrypt([]byte) ([]byte, error)
	// Decrypt 解密数据
	Decrypt([]byte) ([]byte, error)
	// BlockSize 返回加密模式使用的块大小
	BlockSize() int
}

// AuthenticatedMode 接口定义了认证加密模式的方法
type AuthenticatedMode interface {
	Mode
	// Seal 加密并认证数据，附加认证数据可选
	Seal(nonce, plaintext, additionalData []byte) ([]byte, error)
	// Open 解密并验证数据，附加认证数据可选
	Open(nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// PaddingFunc 定义了填充函数的类型
type PaddingFunc func([]byte, int) ([]byte, error)

// UnpaddingFunc 定义了取消填充函数的类型
type UnpaddingFunc func([]byte) ([]byte, error)
