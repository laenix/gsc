package rc5

import (
	"encoding/binary"
	"errors"
	"math"
	"math/bits"
)

const (
	// 块大小（字节）
	BlockSize = 8
	// 默认轮数
	DefaultRounds = 12
	// 默认字长（比特）
	DefaultWordSize = 32
	// 默认密钥长度（字节）
	DefaultKeySize = 16
	// 最小密钥长度（字节）
	MinKeySize = 1
	// 最大密钥长度（字节）
	MaxKeySize = 255
)

// RC5 结构体定义RC5密码
type RC5 struct {
	rounds    int      // 轮数
	wordSize  int      // 字长（位）
	blockSize int      // 块大小（字节）
	keySize   int      // 密钥大小（字节）
	subKeys   []uint32 // 子密钥数组
}

// 错误定义
var (
	ErrInvalidKeySize   = errors.New("rc5: 密钥长度必须在1-255字节之间")
	ErrInvalidBlockSize = errors.New("rc5: 数据块大小不匹配")
	ErrInvalidWordSize  = errors.New("rc5: 字长必须是32位(4字节)或64位(8字节)")
	ErrInvalidRounds    = errors.New("rc5: 轮数必须在1-255之间")
)

// New 创建一个新的RC5实例，使用默认参数(RC5-32/12/16)
func New(key []byte) (*RC5, error) {
	return NewWithParams(key, DefaultRounds, DefaultWordSize)
}

// NewWithParams 创建一个新的RC5实例，可指定轮数和字长
func NewWithParams(key []byte, rounds, wordSize int) (*RC5, error) {
	// 验证密钥长度
	if len(key) < MinKeySize || len(key) > MaxKeySize {
		return nil, ErrInvalidKeySize
	}

	// 验证轮数
	if rounds < 1 || rounds > 255 {
		return nil, ErrInvalidRounds
	}

	// 验证字长，目前仅支持32位
	if wordSize != 32 /* && wordSize != 64 */ {
		return nil, ErrInvalidWordSize
	}

	wordBytes := wordSize / 8
	blockSize := wordBytes * 2

	// 创建RC5实例
	rc5 := &RC5{
		rounds:    rounds,
		wordSize:  wordSize,
		blockSize: blockSize,
		keySize:   len(key),
		subKeys:   make([]uint32, 2*(rounds+1)),
	}

	// 扩展密钥
	rc5.expandKey(key)

	return rc5, nil
}

// BlockSize 返回区块大小
func (r *RC5) BlockSize() int {
	return r.blockSize
}

// Encrypt 加密单个区块
func (r *RC5) Encrypt(block []byte) ([]byte, error) {
	if len(block) != r.blockSize {
		return nil, ErrInvalidBlockSize
	}

	// 创建返回结果
	result := make([]byte, r.blockSize)
	copy(result, block)

	// 读取A和B（两个字）
	var A, B uint32
	if r.wordSize == 32 {
		A = binary.LittleEndian.Uint32(result[0:4])
		B = binary.LittleEndian.Uint32(result[4:8])
	} else {
		// 未实现64位支持
		return nil, ErrInvalidWordSize
	}

	// 执行加密
	A = A + r.subKeys[0]
	B = B + r.subKeys[1]

	for i := 1; i <= r.rounds; i++ {
		A = bits.RotateLeft32((A^B), int(B%32)) + r.subKeys[2*i]
		B = bits.RotateLeft32((B^A), int(A%32)) + r.subKeys[2*i+1]
	}

	// 写回结果
	if r.wordSize == 32 {
		binary.LittleEndian.PutUint32(result[0:4], A)
		binary.LittleEndian.PutUint32(result[4:8], B)
	}

	return result, nil
}

// Decrypt 解密单个区块
func (r *RC5) Decrypt(block []byte) ([]byte, error) {
	if len(block) != r.blockSize {
		return nil, ErrInvalidBlockSize
	}

	// 创建返回结果
	result := make([]byte, r.blockSize)
	copy(result, block)

	// 读取A和B（两个字）
	var A, B uint32
	if r.wordSize == 32 {
		A = binary.LittleEndian.Uint32(result[0:4])
		B = binary.LittleEndian.Uint32(result[4:8])
	} else {
		// 未实现64位支持
		return nil, ErrInvalidWordSize
	}

	// 执行解密（逆序）
	for i := r.rounds; i >= 1; i-- {
		B = bits.RotateLeft32(B-r.subKeys[2*i+1], -int(A%32)) ^ A
		A = bits.RotateLeft32(A-r.subKeys[2*i], -int(B%32)) ^ B
	}

	B = B - r.subKeys[1]
	A = A - r.subKeys[0]

	// 写回结果
	if r.wordSize == 32 {
		binary.LittleEndian.PutUint32(result[0:4], A)
		binary.LittleEndian.PutUint32(result[4:8], B)
	}

	return result, nil
}

// expandKey 生成轮子密钥
func (r *RC5) expandKey(key []byte) {
	// RC5常量
	var P, Q uint32
	if r.wordSize == 32 {
		P = 0xB7E15163 // 32位魔数: odd(e-2)
		Q = 0x9E3779B9 // 32位魔数: odd(phi-1)
	} else {
		// 64位未实现
		P = 0xB7E15163
		Q = 0x9E3779B9
	}

	// 初始化子密钥数组
	r.subKeys[0] = P
	for i := 1; i < len(r.subKeys); i++ {
		r.subKeys[i] = r.subKeys[i-1] + Q
	}

	// 转换密钥为字数组
	wordBytes := r.wordSize / 8
	u := int(math.Ceil(float64(r.keySize) / float64(wordBytes)))
	c := make([]uint32, u)

	for i := 0; i < r.keySize; i++ {
		idx := i / wordBytes
		shift := (i % wordBytes) * 8
		c[idx] = c[idx] | (uint32(key[i]) << shift)
	}

	// 混合
	a, b, i, j := uint32(0), uint32(0), 0, 0
	rounds := 3 * max(len(r.subKeys), len(c))

	for k := 0; k < rounds; k++ {
		a = r.subKeys[i] + a + b
		r.subKeys[i] = bits.RotateLeft32(a, 3)
		i = (i + 1) % len(r.subKeys)

		b = c[j] + a + b
		c[j] = bits.RotateLeft32(b, int(a+b)%32)
		j = (j + 1) % len(c)
	}
}

// max 返回两个整数中的较大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
