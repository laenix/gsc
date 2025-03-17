package des

import (
	"errors"

	"github.com/laenix/gsc/des/internal"
)

const (
	// 区块大小（字节）
	BlockSize = 8
	// 密钥大小（字节）
	KeySize = 8
)

// DES 结构体包含加密和解密所需的轮密钥
type DES struct {
	// 解密和加密的16轮子密钥
	roundKeys [16]uint64
}

// 错误定义
var (
	ErrInvalidKeySize   = errors.New("des: 密钥必须是8字节（64位）")
	ErrInvalidBlockSize = errors.New("des: 数据块必须是8字节（64位）")
)

// New 创建一个新的DES实例
func New(key []byte) (*DES, error) {
	// 验证密钥长度
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	// 创建DES实例
	des := &DES{}

	// 生成轮密钥
	des.generateRoundKeys(key)

	return des, nil
}

// BlockSize 返回区块大小
func (d *DES) BlockSize() int {
	return BlockSize
}

// Encrypt 加密单个区块（8字节）
func (d *DES) Encrypt(block []byte) ([]byte, error) {
	if len(block) != BlockSize {
		return nil, ErrInvalidBlockSize
	}

	// 将8字节转换为64位整数
	input := bytesToUint64(block)

	// 初始置换 (IP)
	state := initialPermutation(input)

	// 16轮Feistel网络操作
	left, right := uint32(state>>32), uint32(state)
	for i := 0; i < 16; i++ {
		newRight := left ^ feistelFunction(right, d.roundKeys[i])
		left, right = right, newRight
	}

	// 交换左右部分
	state = (uint64(right) << 32) | uint64(left)

	// 最终置换 (IP^-1)
	output := finalPermutation(state)

	// 将64位整数转换回8字节
	result := make([]byte, BlockSize)
	uint64ToBytes(output, result)

	return result, nil
}

// Decrypt 解密单个区块（8字节）
func (d *DES) Decrypt(block []byte) ([]byte, error) {
	if len(block) != BlockSize {
		return nil, ErrInvalidBlockSize
	}

	// 将8字节转换为64位整数
	input := bytesToUint64(block)

	// 初始置换 (IP)
	state := initialPermutation(input)

	// 16轮Feistel网络操作 (轮密钥顺序相反)
	left, right := uint32(state>>32), uint32(state)
	for i := 15; i >= 0; i-- {
		newRight := left ^ feistelFunction(right, d.roundKeys[i])
		left, right = right, newRight
	}

	// 交换左右部分
	state = (uint64(right) << 32) | uint64(left)

	// 最终置换 (IP^-1)
	output := finalPermutation(state)

	// 将64位整数转换回8字节
	result := make([]byte, BlockSize)
	uint64ToBytes(output, result)

	return result, nil
}

// generateRoundKeys 从初始密钥生成16轮密钥
func (d *DES) generateRoundKeys(key []byte) {
	// 转换为64位整数
	k := bytesToUint64(key)

	// 密钥置换1 (PC-1)
	var k56 uint64
	for i := 0; i < 56; i++ {
		// 注意：PC-1表中的值是1-based，需要减1
		srcBit := internal.PC1[i] - 1
		if (k>>(63-srcBit))&1 == 1 {
			k56 |= 1 << (55 - i)
		}
	}

	// 分成左右两部分，各28位
	left := (k56 >> 28) & 0x0FFFFFFF
	right := k56 & 0x0FFFFFFF

	// 生成16轮密钥
	for round := 0; round < 16; round++ {
		// 根据轮数决定循环左移的位数
		var shifts uint
		if round == 0 || round == 1 || round == 8 || round == 15 {
			shifts = 1
		} else {
			shifts = 2
		}

		// 循环左移
		left = ((left << shifts) | (left >> (28 - shifts))) & 0x0FFFFFFF
		right = ((right << shifts) | (right >> (28 - shifts))) & 0x0FFFFFFF

		// 合并左右部分
		combined := (left << 28) | right

		// 密钥置换2 (PC-2)
		d.roundKeys[round] = permutedChoice2(combined)
	}
}

// initialPermutation 实现初始置换 (IP)
func initialPermutation(input uint64) uint64 {
	var output uint64
	for i := 0; i < 64; i++ {
		// IP表中的值是1-based，需要减1
		srcBit := internal.IP[i] - 1
		if (input>>(63-srcBit))&1 == 1 {
			output |= 1 << (63 - i)
		}
	}
	return output
}

// finalPermutation 实现最终置换 (IP^-1)
func finalPermutation(input uint64) uint64 {
	var output uint64
	for i := 0; i < 64; i++ {
		// FP表中的值是1-based，需要减1
		srcBit := internal.FP[i] - 1
		if (input>>(63-srcBit))&1 == 1 {
			output |= 1 << (63 - i)
		}
	}
	return output
}

// feistelFunction 实现Feistel轮函数
func feistelFunction(r uint32, key uint64) uint32 {
	// 扩展置换 (E)
	var expanded uint64
	for i := 0; i < 48; i++ {
		// E表中的值是1-based，需要减1
		srcBit := internal.E[i] - 1
		if (uint64(r)>>(31-srcBit))&1 == 1 {
			expanded |= 1 << (47 - i)
		}
	}

	// 与轮密钥异或
	mixed := expanded ^ key

	// S-boxes替换
	var output uint32
	for i := 0; i < 8; i++ {
		// 提取6位输入
		b := byte((mixed >> (42 - i*6)) & 0x3F)

		// 计算S-box的行和列
		// 第一位和最后一位组成行号
		row := ((b & 0x20) >> 4) | (b & 0x01)
		// 中间四位组成列号
		col := (b >> 1) & 0x0F

		// 查表并合并结果
		output = (output << 4) | uint32(internal.SBOXES[i][row*16+col])
	}

	// P-box置换
	var result uint32
	for i := 0; i < 32; i++ {
		// P表中的值是1-based，需要减1
		srcBit := internal.P[i] - 1
		if (output>>(31-srcBit))&1 == 1 {
			result |= 1 << (31 - i)
		}
	}
	return result
}

// permutedChoice2 实现密钥置换2 (PC-2)
func permutedChoice2(input uint64) uint64 {
	var output uint64
	for j := 0; j < 48; j++ {
		// 注意：PC-2表中的值是1-based，需要减1
		srcBit := internal.PC2[j] - 1
		if (input>>(55-srcBit))&1 == 1 {
			output |= 1 << (47 - j)
		}
	}
	return output
}

// bytesToUint64 将8个字节转换为uint64
func bytesToUint64(b []byte) uint64 {
	var result uint64
	for i := 0; i < 8; i++ {
		result = (result << 8) | uint64(b[i])
	}
	return result
}

// uint64ToBytes 将uint64转换为8个字节
func uint64ToBytes(v uint64, result []byte) {
	for i := 7; i >= 0; i-- {
		result[i] = byte(v)
		v >>= 8
	}
}
