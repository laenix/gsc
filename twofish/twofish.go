package twofish

import (
	"errors"
)

const (
	// 块大小
	BlockSize = 16
	// 支持的密钥长度
	KeySize128 = 16
	KeySize192 = 24
	KeySize256 = 32
)

// Twofish 结构体定义Twofish密码
type Twofish struct {
	k       [40]uint32 // 轮密钥
	s       [][]byte   // S-boxes (每个大小为256)
	keySize int        // 密钥长度 (16, 24, 或 32 字节)
}

// 错误定义
var (
	ErrInvalidKeySize   = errors.New("twofish: 密钥长度必须是16, 24或32字节")
	ErrInvalidBlockSize = errors.New("twofish: 数据块必须是16字节")
)

// New 创建一个新的Twofish实例
func New(key []byte) (*Twofish, error) {
	keyLen := len(key)
	if keyLen != KeySize128 && keyLen != KeySize192 && keyLen != KeySize256 {
		return nil, ErrInvalidKeySize
	}

	// 创建Twofish实例
	t := &Twofish{
		keySize: keyLen,
		s:       make([][]byte, 4),
	}

	// 初始化S盒
	for i := 0; i < 4; i++ {
		t.s[i] = make([]byte, 256)
	}

	// 密钥扩展
	t.expandKey(key)

	return t, nil
}

// BlockSize 返回区块大小
func (t *Twofish) BlockSize() int {
	return BlockSize
}

// Encrypt 加密单个区块（16字节）
func (t *Twofish) Encrypt(block []byte) ([]byte, error) {
	if len(block) != BlockSize {
		return nil, ErrInvalidBlockSize
	}

	// 复制输入块以避免就地修改
	result := make([]byte, BlockSize)
	copy(result, block)

	// 将16字节明文分成4个32位字
	w0 := bytesToUint32(result[0:4])
	w1 := bytesToUint32(result[4:8])
	w2 := bytesToUint32(result[8:12])
	w3 := bytesToUint32(result[12:16])

	// 输入白化
	w0 ^= t.k[0]
	w1 ^= t.k[1]
	w2 ^= t.k[2]
	w3 ^= t.k[3]

	// 16轮加密
	k := 8
	for r := 0; r < 16; r += 2 {
		// 第r轮
		t0 := t.g0(w0)
		t1 := t.g1(w1)
		w2 ^= t0 + t1 + t.k[k]
		w2 = (w2 >> 1) | (w2 << 31)                            // 循环右移1位
		w3 = ((w3 << 1) | (w3 >> 31)) ^ (t0 + 2*t1 + t.k[k+1]) // 循环左移1位再XOR

		// 第r+1轮
		t0 = t.g0(w2)
		t1 = t.g1(w3)
		w0 ^= t0 + t1 + t.k[k+2]
		w0 = (w0 >> 1) | (w0 << 31)                            // 循环右移1位
		w1 = ((w1 << 1) | (w1 >> 31)) ^ (t0 + 2*t1 + t.k[k+3]) // 循环左移1位再XOR

		k += 4
	}

	// 输出白化
	w2 ^= t.k[4]
	w3 ^= t.k[5]
	w0 ^= t.k[6]
	w1 ^= t.k[7]

	// 写回结果
	uint32ToBytes(w2, result[0:4])
	uint32ToBytes(w3, result[4:8])
	uint32ToBytes(w0, result[8:12])
	uint32ToBytes(w1, result[12:16])

	return result, nil
}

// Decrypt 解密单个区块（16字节）
func (t *Twofish) Decrypt(block []byte) ([]byte, error) {
	if len(block) != BlockSize {
		return nil, ErrInvalidBlockSize
	}

	// 复制输入块以避免就地修改
	result := make([]byte, BlockSize)
	copy(result, block)

	// 将16字节密文分成4个32位字
	w2 := bytesToUint32(result[0:4])
	w3 := bytesToUint32(result[4:8])
	w0 := bytesToUint32(result[8:12])
	w1 := bytesToUint32(result[12:16])

	// 输入白化（使用输出白化密钥）
	w2 ^= t.k[4]
	w3 ^= t.k[5]
	w0 ^= t.k[6]
	w1 ^= t.k[7]

	// 16轮解密 (逆序)
	k := 36
	for r := 0; r < 16; r += 2 {
		// 第r轮 (逆序)
		t0 := t.g0(w2)
		t1 := t.g1(w3)
		w1 ^= (t0 + 2*t1 + t.k[k+3])
		w1 = (w1 >> 1) | (w1 << 31)                          // 循环右移1位
		w0 = ((w0 << 1) | (w0 >> 31)) ^ (t0 + t1 + t.k[k+2]) // 循环左移1位再XOR

		// 第r+1轮 (逆序)
		t0 = t.g0(w0)
		t1 = t.g1(w1)
		w3 ^= (t0 + 2*t1 + t.k[k+1])
		w3 = (w3 >> 1) | (w3 << 31)                        // 循环右移1位
		w2 = ((w2 << 1) | (w2 >> 31)) ^ (t0 + t1 + t.k[k]) // 循环左移1位再XOR

		k -= 4
	}

	// 输出白化（使用输入白化密钥）
	w0 ^= t.k[0]
	w1 ^= t.k[1]
	w2 ^= t.k[2]
	w3 ^= t.k[3]

	// 写回结果
	uint32ToBytes(w0, result[0:4])
	uint32ToBytes(w1, result[4:8])
	uint32ToBytes(w2, result[8:12])
	uint32ToBytes(w3, result[12:16])

	return result, nil
}

// g0和g1是Twofish的G函数
func (t *Twofish) g0(x uint32) uint32 {
	// 分解x为4个字节
	b0 := byte(x)
	b1 := byte(x >> 8)
	b2 := byte(x >> 16)
	b3 := byte(x >> 24)

	// 应用S盒替换
	y0 := uint32(t.s[0][b0]) ^ uint32(t.s[1][b1]) ^ uint32(t.s[2][b2]) ^ uint32(t.s[3][b3])
	return y0
}

func (t *Twofish) g1(x uint32) uint32 {
	// 分解x为4个字节，并旋转字节顺序
	b0 := byte(x >> 8)
	b1 := byte(x >> 16)
	b2 := byte(x >> 24)
	b3 := byte(x)

	// 应用S盒替换
	y1 := uint32(t.s[0][b0]) ^ uint32(t.s[1][b1]) ^ uint32(t.s[2][b2]) ^ uint32(t.s[3][b3])
	return y1
}

// expandKey 执行Twofish密钥扩展
func (t *Twofish) expandKey(key []byte) {
	// 这里是简化版的Twofish密钥扩展算法
	// 实际实现需要考虑Reed-Solomon编码和MDS矩阵变换

	// 初始化S盒 (简化)
	for i := 0; i < 4; i++ {
		for j := 0; j < 256; j++ {
			t.s[i][j] = byte((j*i + int(key[j%len(key)])) % 256)
		}
	}

	// 生成轮密钥 (简化)
	for i := 0; i < 40; i++ {
		t.k[i] = uint32(i) * 0x01010101
		for j := 0; j < len(key); j++ {
			t.k[i] ^= uint32(key[j]) << ((j % 4) * 8)
		}
	}
}

// 辅助函数

// bytesToUint32 将4个字节转换为uint32 (大端序)
func bytesToUint32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// uint32ToBytes 将uint32转换为4个字节 (大端序)
func uint32ToBytes(v uint32, b []byte) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}
