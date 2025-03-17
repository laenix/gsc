package modes

import (
	"gsc/modes/internal"
	"gsc/padding"
)

// CBC 结构体实现了密码块链接(CBC)模式
type CBC struct {
	cipher   BlockCipher
	iv       []byte
	padder   PaddingFunc
	unpadder UnpaddingFunc
}

// NewCBC 创建一个新的CBC模式封装器
func NewCBC(cipher BlockCipher, iv []byte) (*CBC, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, ErrInvalidIV
	}

	// 复制iv避免外部修改
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	return &CBC{
		cipher:   cipher,
		iv:       ivCopy,
		padder:   padding.PKCS7Padding,
		unpadder: padding.PKCS7Unpadding,
	}, nil
}

// WithPadding 设置自定义填充方法
func (c *CBC) WithPadding(padder PaddingFunc, unpadder UnpaddingFunc) *CBC {
	c.padder = padder
	c.unpadder = unpadder
	return c
}

// Encrypt 使用CBC模式加密数据（不含填充，要求输入长度为块大小的整数倍）
func (c *CBC) Encrypt(plaintext []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()

	// 验证明文长度是否为块大小的整数倍
	if len(plaintext)%blockSize != 0 {
		return nil, ErrInvalidDataSize
	}

	// 初始化向量
	prev := make([]byte, blockSize)
	copy(prev, c.iv)

	ciphertext := make([]byte, len(plaintext))

	// 逐块加密
	for i := 0; i < len(plaintext); i += blockSize {
		// 1. 明文块与前一个密文块（或初始向量）异或
		block := make([]byte, blockSize)
		internal.XORBytes(block, plaintext[i:i+blockSize], prev)

		// 2. 加密结果
		encryptedBlock, err := c.cipher.Encrypt(block)
		if err != nil {
			return nil, err
		}

		// 3. 复制结果到密文输出
		copy(ciphertext[i:i+blockSize], encryptedBlock)

		// 4. 更新前一个块
		copy(prev, encryptedBlock)
	}

	return ciphertext, nil
}

// Decrypt 使用CBC模式解密数据（不移除填充，要求输入长度为块大小的整数倍）
func (c *CBC) Decrypt(ciphertext []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()

	// 验证密文长度是否为块大小的整数倍
	if len(ciphertext)%blockSize != 0 {
		return nil, ErrInvalidDataSize
	}

	// 初始化向量
	prev := make([]byte, blockSize)
	copy(prev, c.iv)

	plaintext := make([]byte, len(ciphertext))

	// 逐块解密
	for i := 0; i < len(ciphertext); i += blockSize {
		// 1. 解密当前密文块
		decryptedBlock, err := c.cipher.Decrypt(ciphertext[i : i+blockSize])
		if err != nil {
			return nil, err
		}

		// 2. 将解密结果与前一个密文块（或初始向量）异或
		internal.XORBytes(plaintext[i:i+blockSize], decryptedBlock, prev)

		// 3. 更新前一个块
		copy(prev, ciphertext[i:i+blockSize])
	}

	return plaintext, nil
}

// EncryptPadded 使用填充方法加密任意长度的数据
func (c *CBC) EncryptPadded(plaintext []byte) ([]byte, error) {
	if c.padder == nil {
		return nil, ErrInvalidPadding
	}
	padded := c.padder(plaintext, c.cipher.BlockSize())
	return c.Encrypt(padded)
}

// DecryptPadded 解密并移除填充
func (c *CBC) DecryptPadded(ciphertext []byte) ([]byte, error) {
	if c.unpadder == nil {
		return nil, ErrInvalidPadding
	}
	plaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	return c.unpadder(plaintext)
}

// BlockSize 返回块大小
func (c *CBC) BlockSize() int {
	return c.cipher.BlockSize()
}
