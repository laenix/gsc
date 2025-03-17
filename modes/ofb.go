package modes

import "github.com/laenix/gsc/modes/internal"

// OFB 结构体实现了输出反馈(OFB)模式
type OFB struct {
	cipher BlockCipher
	iv     []byte
}

// NewOFB 创建一个新的OFB模式封装器
func NewOFB(cipher BlockCipher, iv []byte) (*OFB, error) {
	blockSize := cipher.BlockSize()
	if len(iv) != blockSize {
		return nil, ErrInvalidIV
	}

	// 复制iv避免外部修改
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	return &OFB{
		cipher: cipher,
		iv:     ivCopy,
	}, nil
}

// Encrypt 使用OFB模式加密数据
func (o *OFB) Encrypt(plaintext []byte) ([]byte, error) {
	blockSize := o.cipher.BlockSize()

	// OFB模式可以处理任意长度的数据，不需要填充
	ciphertext := make([]byte, len(plaintext))

	// 初始化寄存器
	register := make([]byte, blockSize)
	copy(register, o.iv)

	// 处理完整块
	i := 0
	for ; i+blockSize <= len(plaintext); i += blockSize {
		// 1. 加密寄存器
		encryptedRegister, err := o.cipher.Encrypt(register)
		if err != nil {
			return nil, err
		}

		// 2. 将加密后的寄存器与明文异或
		internal.XORBytes(ciphertext[i:i+blockSize], plaintext[i:i+blockSize], encryptedRegister)

		// 3. 更新寄存器为加密后的结果（而不是密文）
		copy(register, encryptedRegister)
	}

	// 处理最后一个不完整块
	if i < len(plaintext) {
		encryptedRegister, err := o.cipher.Encrypt(register)
		if err != nil {
			return nil, err
		}

		// 处理剩余字节
		internal.XORBytes(ciphertext[i:], plaintext[i:], encryptedRegister)
	}

	return ciphertext, nil
}

// Decrypt 使用OFB模式解密数据（在OFB模式中，解密操作与加密操作相同）
func (o *OFB) Decrypt(ciphertext []byte) ([]byte, error) {
	// 由于OFB模式是将密钥流与数据异或，解密和加密操作相同
	return o.Encrypt(ciphertext)
}

// BlockSize 返回块大小
func (o *OFB) BlockSize() int {
	return o.cipher.BlockSize()
}
