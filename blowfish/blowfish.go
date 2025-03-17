package blowfish

import (
	"encoding/binary"
	"errors"

	"github.com/laenix/gsc/blowfish/internal"
)

const (
	// 块大小（字节）
	BlockSize = 8
	// 最小密钥长度
	MinKeySize = 4
	// 最大密钥长度
	MaxKeySize = 56
)

// Blowfish 结构体定义Blowfish密码
type Blowfish struct {
	p [18]uint32     // P-box
	s [4][256]uint32 // S-boxes
}

// 错误定义
var (
	ErrInvalidKeySize   = errors.New("blowfish: 密钥长度必须在4-56字节之间")
	ErrInvalidBlockSize = errors.New("blowfish: 数据块必须是8字节")
)

// New 创建一个新的Blowfish实例
func New(key []byte) (*Blowfish, error) {
	// 验证密钥长度
	if len(key) < MinKeySize || len(key) > MaxKeySize {
		return nil, ErrInvalidKeySize
	}

	// 创建Blowfish实例
	b := &Blowfish{}

	// 初始化P和S盒
	b.initBoxes()

	// 使用密钥修改P盒和S盒
	b.expandKey(key)

	return b, nil
}

// BlockSize 返回区块大小
func (b *Blowfish) BlockSize() int {
	return BlockSize
}

// Encrypt 加密单个区块（8字节）
func (b *Blowfish) Encrypt(block []byte) ([]byte, error) {
	if len(block) != BlockSize {
		return nil, ErrInvalidBlockSize
	}

	result := make([]byte, BlockSize)
	copy(result, block)

	// 将输入分成两个32位部分
	left := binary.BigEndian.Uint32(result[0:4])
	right := binary.BigEndian.Uint32(result[4:8])

	// 进行16轮Feistel网络操作
	left, right = b.encryptBlock(left, right)

	// 将结果写回byte切片
	binary.BigEndian.PutUint32(result[0:4], left)
	binary.BigEndian.PutUint32(result[4:8], right)

	return result, nil
}

// Decrypt 解密单个区块（8字节）
func (b *Blowfish) Decrypt(block []byte) ([]byte, error) {
	if len(block) != BlockSize {
		return nil, ErrInvalidBlockSize
	}

	result := make([]byte, BlockSize)
	copy(result, block)

	// 将输入分成两个32位部分
	left := binary.BigEndian.Uint32(result[0:4])
	right := binary.BigEndian.Uint32(result[4:8])

	// 进行16轮Feistel网络操作（反向）
	left, right = b.decryptBlock(left, right)

	// 将结果写回byte切片
	binary.BigEndian.PutUint32(result[0:4], left)
	binary.BigEndian.PutUint32(result[4:8], right)

	return result, nil
}

// encryptBlock 对一个块进行加密操作
func (b *Blowfish) encryptBlock(left, right uint32) (uint32, uint32) {
	for i := 0; i < 16; i++ {
		left ^= b.p[i]
		right ^= b.feistel(left)
		left, right = right, left
	}

	// 最后一轮交换
	left, right = right, left

	// 最后的处理
	right ^= b.p[16]
	left ^= b.p[17]

	return left, right
}

// decryptBlock 对一个块进行解密操作
func (b *Blowfish) decryptBlock(left, right uint32) (uint32, uint32) {
	for i := 17; i > 1; i-- {
		left ^= b.p[i]
		right ^= b.feistel(left)
		left, right = right, left
	}

	// 最后一轮交换
	left, right = right, left

	// 最后的处理
	right ^= b.p[1]
	left ^= b.p[0]

	return left, right
}

// feistel 为Blowfish的F函数
func (b *Blowfish) feistel(x uint32) uint32 {
	// 分解x为4个字节
	a := (x >> 24) & 0xFF
	b1 := (x >> 16) & 0xFF
	c := (x >> 8) & 0xFF
	d := x & 0xFF

	// 应用S盒并组合结果
	return ((b.s[0][a] + b.s[1][b1]) ^ b.s[2][c]) + b.s[3][d]
}

// initBoxes 初始化P盒和S盒为固定值
func (b *Blowfish) initBoxes() {
	// 初始化P盒为常量值
	copy(b.p[:], internal.PBox[:])

	// 初始化S盒为常量值
	copy(b.s[0][:], internal.SBox0[:])
	copy(b.s[1][:], internal.SBox1[:])
	copy(b.s[2][:], internal.SBox2[:])
	copy(b.s[3][:], internal.SBox3[:])
}

// expandKey 使用密钥修改P盒和S盒
func (b *Blowfish) expandKey(key []byte) {
	j := 0
	for i := 0; i < 18; i++ {
		// 用密钥的每个字节XOR P盒
		var data uint32
		for k := 0; k < 4; k++ {
			data = (data << 8) | uint32(key[j%len(key)])
			j++
		}
		b.p[i] ^= data
	}

	// 使用Blowfish算法的加密过程进一步混合P盒和S盒
	var l, r uint32
	for i := 0; i < 18; i += 2 {
		l, r = b.encryptBlock(l, r)
		b.p[i] = l
		b.p[i+1] = r
	}

	// 更新S盒
	for i := 0; i < 4; i++ {
		for j := 0; j < 256; j += 2 {
			l, r = b.encryptBlock(l, r)
			b.s[i][j] = l
			b.s[i][j+1] = r
		}
	}
}
