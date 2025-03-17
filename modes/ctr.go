package modes

import (
	"github.com/laenix/gsc/modes/internal"
)

// CTR 结构体实现了计数器(CTR)模式
type CTR struct {
	cipher  BlockCipher
	counter []byte
}

// NewCTR 创建一个新的CTR模式封装器
func NewCTR(cipher BlockCipher, initialCounter []byte) (*CTR, error) {
	blockSize := cipher.BlockSize()
	if len(initialCounter) != blockSize {
		return nil, ErrInvalidIV
	}

	// 复制计数器避免外部修改
	counterCopy := make([]byte, len(initialCounter))
	copy(counterCopy, initialCounter)

	return &CTR{
		cipher:  cipher,
		counter: counterCopy,
	}, nil
}

// Encrypt 使用CTR模式加密数据
func (c *CTR) Encrypt(plaintext []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()

	// CTR模式可以处理任意长度的数据，不需要填充
	ciphertext := make([]byte, len(plaintext))

	// 复制计数器，避免修改原始计数器
	counter := make([]byte, blockSize)
	copy(counter, c.counter)

	// 处理数据
	for i := 0; i < len(plaintext); {
		// 1. 加密计数器
		encryptedCounter, err := c.cipher.Encrypt(counter)
		if err != nil {
			return nil, err
		}

		// 2. 计算要处理的字节数（处理最后一个不完整的块）
		n := blockSize
		if i+n > len(plaintext) {
			n = len(plaintext) - i
		}

		// 3. 将加密后的计数器与明文异或
		for j := 0; j < n; j++ {
			ciphertext[i+j] = plaintext[i+j] ^ encryptedCounter[j]
		}

		// 4. 递增计数器
		internal.Increment(counter)

		// 5. 更新索引
		i += n
	}

	return ciphertext, nil
}

// Decrypt 使用CTR模式解密数据（在CTR模式中，解密操作与加密操作相同）
func (c *CTR) Decrypt(ciphertext []byte) ([]byte, error) {
	// 由于CTR模式是将加密后的计数器与数据异或，解密和加密操作相同
	return c.Encrypt(ciphertext)
}

// BlockSize 返回块大小
func (c *CTR) BlockSize() int {
	return c.cipher.BlockSize()
}
