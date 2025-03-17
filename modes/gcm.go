package modes

import (
	"bytes"
	"errors"
	"gsc/modes/internal"
)

const (
	// 默认的GCM认证标签长度（字节）
	defaultGCMTagSize = 16
	// 默认的GCM nonce长度（字节）
	defaultGCMNonceSize = 12
)

// GCM 结构体实现了伽罗瓦计数器模式 (GCM)
type GCM struct {
	cipher  BlockCipher
	tagSize int
	// H = cipher(zeros)
	h []byte
}

// NewGCM 创建一个新的GCM模式封装器
func NewGCM(cipher BlockCipher) (*GCM, error) {
	return NewGCMWithTagSize(cipher, defaultGCMTagSize)
}

// NewGCMWithTagSize 创建一个自定义标签大小的GCM模式封装器
func NewGCMWithTagSize(cipher BlockCipher, tagSize int) (*GCM, error) {
	if tagSize < 4 || tagSize > 16 {
		return nil, errors.New("gcm: 标签大小必须在4和16之间")
	}

	if cipher.BlockSize() != 16 {
		return nil, errors.New("gcm: 需要块大小为16字节的加密算法")
	}

	// 计算H = E(0)
	zeros := make([]byte, 16)
	h, err := cipher.Encrypt(zeros)
	if err != nil {
		return nil, err
	}

	return &GCM{
		cipher:  cipher,
		tagSize: tagSize,
		h:       h,
	}, nil
}

// NonceSize 返回GCM的nonce大小
func (g *GCM) NonceSize() int {
	return defaultGCMNonceSize
}

// Overhead 返回额外数据长度（认证标签的长度）
func (g *GCM) Overhead() int {
	return g.tagSize
}

// Seal 加密数据并添加认证标签
func (g *GCM) Seal(nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != defaultGCMNonceSize {
		return nil, ErrInvalidNonce
	}

	// 1. 派生初始计数器 J0
	j0 := g.deriveJ0(nonce)

	// 2. 递增J0得到实际加密用的计数器值
	counter := make([]byte, 16)
	copy(counter, j0)
	internal.Increment(counter)

	// 3. 使用CTR模式加密明文
	ctrMode, err := NewCTR(g.cipher, counter)
	if err != nil {
		return nil, err
	}

	ciphertext, err := ctrMode.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	// 4. 计算认证标签
	tag := g.computeTag(j0, additionalData, ciphertext)

	// 5. 将认证标签追加到密文后
	return append(ciphertext, tag[:g.tagSize]...), nil
}

// Open 解密数据并验证认证标签
func (g *GCM) Open(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != defaultGCMNonceSize {
		return nil, ErrInvalidNonce
	}

	if len(ciphertext) < g.tagSize {
		return nil, ErrInvalidDataSize
	}

	// 1. 分离密文和认证标签
	tagStart := len(ciphertext) - g.tagSize
	actualCiphertext := ciphertext[:tagStart]
	tag := ciphertext[tagStart:]

	// 2. 派生初始计数器 J0
	j0 := g.deriveJ0(nonce)

	// 3. 计算认证标签
	expectedTag := g.computeTag(j0, additionalData, actualCiphertext)

	// 4. 验证标签
	if !bytes.Equal(expectedTag[:g.tagSize], tag) {
		return nil, ErrTagMismatch
	}

	// 5. 递增J0得到实际解密用的计数器值
	counter := make([]byte, 16)
	copy(counter, j0)
	internal.Increment(counter)

	// 6. 使用CTR模式解密密文
	ctrMode, err := NewCTR(g.cipher, counter)
	if err != nil {
		return nil, err
	}

	plaintext, err := ctrMode.Decrypt(actualCiphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Encrypt GCM不直接支持Encrypt/Decrypt，必须使用Seal/Open
func (g *GCM) Encrypt(plaintext []byte) ([]byte, error) {
	return nil, errors.New("gcm: 必须通过Seal/Open方法使用GCM模式")
}

// Decrypt GCM不直接支持Encrypt/Decrypt，必须使用Seal/Open
func (g *GCM) Decrypt(ciphertext []byte) ([]byte, error) {
	return nil, errors.New("gcm: 必须通过Seal/Open方法使用GCM模式")
}

// BlockSize 返回块大小
func (g *GCM) BlockSize() int {
	return g.cipher.BlockSize()
}

// deriveJ0 派生初始计数器 J0
func (g *GCM) deriveJ0(nonce []byte) []byte {
	// 如果nonce长度是12字节（96位），则直接附加0x00000001
	if len(nonce) == defaultGCMNonceSize {
		j0 := make([]byte, 16)
		copy(j0, nonce)
		j0[15] = 1
		return j0
	}

	// 否则，使用GHASH计算J0
	// 注意：在实际实现中，我们应该考虑非12字节nonce的情况
	// 这里为简化，先假设nonce总是12字节
	return nil
}

// computeTag 计算认证标签
func (g *GCM) computeTag(j0 []byte, aad, ciphertext []byte) []byte {
	// 对齐AAD为16字节的倍数
	paddedAAD := internal.DuplicateSlice(aad)
	if len(paddedAAD)%16 != 0 {
		padding := make([]byte, 16-(len(paddedAAD)%16))
		paddedAAD = append(paddedAAD, padding...)
	}

	// 对齐密文为16字节的倍数
	paddedCiphertext := internal.DuplicateSlice(ciphertext)
	if len(paddedCiphertext)%16 != 0 {
		padding := make([]byte, 16-(len(paddedCiphertext)%16))
		paddedCiphertext = append(paddedCiphertext, padding...)
	}

	return internal.GMAC(g.h, j0, paddedAAD, paddedCiphertext)
}
