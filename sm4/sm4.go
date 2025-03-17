package sm4

import (
	"encoding/binary"
	"errors"

	"github.com/laenix/gsc/sm4/internal"
)

const (
	// 块大小（字节）
	BlockSize = 16
	// 密钥长度（字节）
	KeySize = 16
)

// SM4 结构体定义SM4密码
type SM4 struct {
	roundKeys [32]uint32 // 轮密钥
}

// 错误定义
var (
	ErrInvalidKeySize   = errors.New("sm4: 密钥长度必须是16字节（128位）")
	ErrInvalidBlockSize = errors.New("sm4: 数据块长度必须是16字节（128位）")
)

// New 创建一个新的SM4实例
func New(key []byte) (*SM4, error) {
	// 验证密钥长度
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	// 创建SM4实例
	sm4 := &SM4{}

	// 生成轮密钥
	sm4.expandKey(key)

	return sm4, nil
}

// BlockSize 返回区块大小
func (s *SM4) BlockSize() int {
	return BlockSize
}

// Encrypt 加密单个区块（16字节）
func (s *SM4) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) != BlockSize {
		return nil, ErrInvalidBlockSize
	}

	// 将输入转为4个32位字
	X := make([]uint32, 4)
	X[0] = binary.BigEndian.Uint32(plaintext[0:4])
	X[1] = binary.BigEndian.Uint32(plaintext[4:8])
	X[2] = binary.BigEndian.Uint32(plaintext[8:12])
	X[3] = binary.BigEndian.Uint32(plaintext[12:16])

	// 32轮加密
	for i := 0; i < 32; i++ {
		X[0], X[1], X[2], X[3] = X[1], X[2], X[3], X[0]^feistelFunction(X[1]^X[2]^X[3]^s.roundKeys[i])
	}

	// 反序输出结果
	result := make([]byte, BlockSize)
	binary.BigEndian.PutUint32(result[0:4], X[3])
	binary.BigEndian.PutUint32(result[4:8], X[2])
	binary.BigEndian.PutUint32(result[8:12], X[1])
	binary.BigEndian.PutUint32(result[12:16], X[0])

	return result, nil
}

// Decrypt 解密单个区块（16字节）
func (s *SM4) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != BlockSize {
		return nil, ErrInvalidBlockSize
	}

	// 将输入转为4个32位字
	X := make([]uint32, 4)
	X[0] = binary.BigEndian.Uint32(ciphertext[0:4])
	X[1] = binary.BigEndian.Uint32(ciphertext[4:8])
	X[2] = binary.BigEndian.Uint32(ciphertext[8:12])
	X[3] = binary.BigEndian.Uint32(ciphertext[12:16])

	// 32轮解密（使用逆序轮密钥）
	for i := 31; i >= 0; i-- {
		X[0], X[1], X[2], X[3] = X[1], X[2], X[3], X[0]^feistelFunction(X[1]^X[2]^X[3]^s.roundKeys[i])
	}

	// 反序输出结果
	result := make([]byte, BlockSize)
	binary.BigEndian.PutUint32(result[0:4], X[3])
	binary.BigEndian.PutUint32(result[4:8], X[2])
	binary.BigEndian.PutUint32(result[8:12], X[1])
	binary.BigEndian.PutUint32(result[12:16], X[0])

	return result, nil
}

// expandKey 生成轮密钥
func (s *SM4) expandKey(key []byte) {
	// 将密钥转为4个32位字
	MK := make([]uint32, 4)
	MK[0] = binary.BigEndian.Uint32(key[0:4])
	MK[1] = binary.BigEndian.Uint32(key[4:8])
	MK[2] = binary.BigEndian.Uint32(key[8:12])
	MK[3] = binary.BigEndian.Uint32(key[12:16])

	// 密钥扩展算法
	K := make([]uint32, 36)
	K[0] = MK[0] ^ internal.FK[0]
	K[1] = MK[1] ^ internal.FK[1]
	K[2] = MK[2] ^ internal.FK[2]
	K[3] = MK[3] ^ internal.FK[3]

	// 生成轮密钥
	for i := 0; i < 32; i++ {
		K[i+4] = K[i] ^ keyTransform(K[i+1]^K[i+2]^K[i+3]^internal.CK[i])
		s.roundKeys[i] = K[i+4]
	}
}

// keyTransform 为密钥扩展中的T'变换，与加密中的T变换略有不同
func keyTransform(input uint32) uint32 {
	// 非线性变换τ（S盒替换）
	a := byte(input >> 24)
	b := byte(input >> 16)
	c := byte(input >> 8)
	d := byte(input)

	a = internal.SBOX[a]
	b = internal.SBOX[b]
	c = internal.SBOX[c]
	d = internal.SBOX[d]

	// 线性变换L'
	ret := uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
	return ret ^ rotateLeft(ret, 13) ^ rotateLeft(ret, 23)
}

// feistelFunction 为SM4的T变换（加密过程中使用）
func feistelFunction(input uint32) uint32 {
	// 非线性变换τ（S盒替换）
	a := byte(input >> 24)
	b := byte(input >> 16)
	c := byte(input >> 8)
	d := byte(input)

	a = internal.SBOX[a]
	b = internal.SBOX[b]
	c = internal.SBOX[c]
	d = internal.SBOX[d]

	// 线性变换L
	ret := uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
	return ret ^ rotateLeft(ret, 2) ^ rotateLeft(ret, 10) ^ rotateLeft(ret, 18) ^ rotateLeft(ret, 24)
}

// rotateLeft 循环左移
func rotateLeft(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}
