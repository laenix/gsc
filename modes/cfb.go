package modes

import (
	"github.com/laenix/gsc/modes/internal"
)

// CFB 结构体实现了密码反馈(CFB)模式
type CFB struct {
	cipher BlockCipher
	iv     []byte
	// segment size，通常等于blockSize，但CFB模式允许更小的段大小
	segmentSize int
}

// NewCFB 创建一个新的CFB模式封装器
func NewCFB(cipher BlockCipher, iv []byte) (*CFB, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, ErrInvalidIV
	}

	// 复制iv避免外部修改
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	return &CFB{
		cipher:      cipher,
		iv:          ivCopy,
		segmentSize: blockSize,
	}, nil
}

// WithSegmentSize 设置CFB的段大小
func (c *CFB) WithSegmentSize(segmentSize int) (*CFB, error) {
	if segmentSize <= 0 || segmentSize > c.cipher.BlockSize() {
		return nil, ErrInvalidBlockSize
	}
	c.segmentSize = segmentSize
	return c, nil
}

// Encrypt 使用CFB模式加密数据
func (c *CFB) Encrypt(plaintext []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()

	// CFB模式可以处理任意长度的数据，不需要填充
	ciphertext := make([]byte, len(plaintext))

	// 初始化寄存器
	register := make([]byte, blockSize)
	copy(register, c.iv)

	// 分段处理数据
	for i := 0; i < len(plaintext); i += c.segmentSize {
		// 1. 加密寄存器
		encrypted, err := c.cipher.Encrypt(register)
		if err != nil {
			return nil, err
		}

		// 2. 计算要处理的字节数（处理最后一个不完整的分段）
		n := c.segmentSize
		if i+n > len(plaintext) {
			n = len(plaintext) - i
		}

		// 3. 输出 = 明文 XOR 加密后的寄存器
		internal.XORBytes(ciphertext[i:i+n], plaintext[i:i+n], encrypted[:n])

		// 4. 更新寄存器 - 移位并添加新的密文
		if blockSize > c.segmentSize {
			// 如果分段大小小于块大小，需要移位
			copy(register, register[c.segmentSize:])
			copy(register[blockSize-c.segmentSize:], ciphertext[i:i+n])
		} else {
			// 分段大小等于块大小的情况
			copy(register, ciphertext[i:i+n])
		}
	}

	return ciphertext, nil
}

// Decrypt 使用CFB模式解密数据
func (c *CFB) Decrypt(ciphertext []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()

	// CFB模式可以处理任意长度的数据
	plaintext := make([]byte, len(ciphertext))

	// 初始化寄存器
	register := make([]byte, blockSize)
	copy(register, c.iv)

	// 分段处理数据
	for i := 0; i < len(ciphertext); i += c.segmentSize {
		// 1. 加密寄存器
		encrypted, err := c.cipher.Encrypt(register)
		if err != nil {
			return nil, err
		}

		// 2. 计算要处理的字节数（处理最后一个不完整的分段）
		n := c.segmentSize
		if i+n > len(ciphertext) {
			n = len(ciphertext) - i
		}

		// 3. 输出 = 密文 XOR 加密后的寄存器
		internal.XORBytes(plaintext[i:i+n], ciphertext[i:i+n], encrypted[:n])

		// 4. 更新寄存器 - 移位并添加新的密文
		if blockSize > c.segmentSize {
			// 如果分段大小小于块大小，需要移位
			copy(register, register[c.segmentSize:])
			copy(register[blockSize-c.segmentSize:], ciphertext[i:i+n])
		} else {
			// 分段大小等于块大小的情况
			copy(register, ciphertext[i:i+n])
		}
	}

	return plaintext, nil
}

// BlockSize 返回块大小
func (c *CFB) BlockSize() int {
	return c.cipher.BlockSize()
}
