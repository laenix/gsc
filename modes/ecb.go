package modes

import (
	"gsc/padding"
)

// ECB 结构体实现了电子密码本(ECB)模式
type ECB struct {
	cipher   BlockCipher
	padder   PaddingFunc
	unpadder UnpaddingFunc
}

// NewECB 创建一个新的ECB模式封装器
func NewECB(cipher BlockCipher) *ECB {
	return &ECB{
		cipher:   cipher,
		padder:   padding.PKCS7Padding,
		unpadder: padding.PKCS7Unpadding,
	}
}

// WithPadding 设置自定义填充方法
func (e *ECB) WithPadding(padder PaddingFunc, unpadder UnpaddingFunc) *ECB {
	e.padder = padder
	e.unpadder = unpadder
	return e
}

// Encrypt 使用ECB模式加密数据（不含填充，要求输入长度为块大小的整数倍）
// 注意：ECB不安全，不推荐用于生产环境
func (e *ECB) Encrypt(plaintext []byte) ([]byte, error) {
	blockSize := e.cipher.BlockSize()

	// 验证明文长度是否为块大小的整数倍
	if len(plaintext)%blockSize != 0 {
		return nil, ErrInvalidDataSize
	}

	ciphertext := make([]byte, len(plaintext))

	// 逐块加密
	for i := 0; i < len(plaintext); i += blockSize {
		block, err := e.cipher.Encrypt(plaintext[i : i+blockSize])
		if err != nil {
			return nil, err
		}
		copy(ciphertext[i:i+blockSize], block)
	}

	return ciphertext, nil
}

// Decrypt 使用ECB模式解密数据（不移除填充，要求输入长度为块大小的整数倍）
func (e *ECB) Decrypt(ciphertext []byte) ([]byte, error) {
	blockSize := e.cipher.BlockSize()

	// 验证密文长度是否为块大小的整数倍
	if len(ciphertext)%blockSize != 0 {
		return nil, ErrInvalidDataSize
	}

	plaintext := make([]byte, len(ciphertext))

	// 逐块解密
	for i := 0; i < len(ciphertext); i += blockSize {
		block, err := e.cipher.Decrypt(ciphertext[i : i+blockSize])
		if err != nil {
			return nil, err
		}
		copy(plaintext[i:i+blockSize], block)
	}

	return plaintext, nil
}

// EncryptPadded 使用填充方法加密任意长度的数据
func (e *ECB) EncryptPadded(plaintext []byte) ([]byte, error) {
	if e.padder == nil {
		return nil, ErrInvalidPadding
	}
	padded := e.padder(plaintext, e.cipher.BlockSize())
	return e.Encrypt(padded)
}

// DecryptPadded 解密并移除填充
func (e *ECB) DecryptPadded(ciphertext []byte) ([]byte, error) {
	if e.unpadder == nil {
		return nil, ErrInvalidPadding
	}
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return e.unpadder(plaintext)
}

// BlockSize 返回块大小
func (e *ECB) BlockSize() int {
	return e.cipher.BlockSize()
}
