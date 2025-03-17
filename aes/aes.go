package aes

import (
	"errors"
	"gsc/aes/internal"
)

const (
	// AES-128, AES-192, AES-256 的密钥长度（字节）
	KeySize128 = 16
	KeySize192 = 24
	KeySize256 = 32
)

// AES 结构体定义AES密码
type AES struct {
	roundKeys []uint32 // 扩展密钥
	rounds    int      // 轮数：AES-128为10，AES-192为12，AES-256为14
}

// New 创建一个新的AES实例
func New(key []byte) (*AES, error) {
	keyLength := len(key)
	var rounds int

	switch keyLength {
	case KeySize128:
		rounds = 10
	case KeySize192:
		rounds = 12
	case KeySize256:
		rounds = 14
	default:
		return nil, errors.New("无效的密钥长度，必须是16, 24或32字节")
	}

	a := &AES{
		rounds: rounds,
	}
	a.expandKey(key)
	return a, nil
}

// expandKey 生成AES的子密钥
func (a *AES) expandKey(key []byte) {
	nk := len(key) / 4 // 密钥长度（字数）
	a.roundKeys = make([]uint32, (a.rounds+1)*4)

	// 复制原始密钥
	for i := 0; i < nk; i++ {
		a.roundKeys[i] = uint32(key[4*i])<<24 | uint32(key[4*i+1])<<16 | uint32(key[4*i+2])<<8 | uint32(key[4*i+3])
	}

	// 扩展密钥
	for i := nk; i < len(a.roundKeys); i++ {
		temp := a.roundKeys[i-1]
		if i%nk == 0 {
			// 每nk个字进行一次SubWord和RotWord
			temp = subWord(rotWord(temp)) ^ internal.RCON[i/nk-1]
		} else if nk > 6 && i%nk == 4 {
			// AES-256的额外操作
			temp = subWord(temp)
		}
		a.roundKeys[i] = a.roundKeys[i-nk] ^ temp
	}
}

// Encrypt 加密单个数据块（16字节）
func (a *AES) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) != 16 {
		return nil, errors.New("明文块长度必须为16字节")
	}

	state := make([]byte, 16)
	copy(state, plaintext)

	// 初始轮密钥加
	a.addRoundKey(state, 0)

	// 主轮
	for round := 1; round < a.rounds; round++ {
		a.subBytes(state)
		a.shiftRows(state)
		a.mixColumns(state)
		a.addRoundKey(state, round)
	}

	// 最后一轮(无mixColumns)
	a.subBytes(state)
	a.shiftRows(state)
	a.addRoundKey(state, a.rounds)

	return state, nil
}

// Decrypt 解密单个数据块（16字节）
func (a *AES) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) != 16 {
		return nil, errors.New("密文块长度必须为16字节")
	}

	state := make([]byte, 16)
	copy(state, ciphertext)

	// 初始轮密钥加
	a.addRoundKey(state, a.rounds)

	// 主轮
	for round := a.rounds - 1; round > 0; round-- {
		a.invShiftRows(state)
		a.invSubBytes(state)
		a.addRoundKey(state, round)
		a.invMixColumns(state)
	}

	// 最后一轮
	a.invShiftRows(state)
	a.invSubBytes(state)
	a.addRoundKey(state, 0)

	return state, nil
}

// 子字节变换
func (a *AES) subBytes(state []byte) {
	for i := 0; i < 16; i++ {
		state[i] = internal.SBOX[state[i]]
	}
}

// 逆子字节变换
func (a *AES) invSubBytes(state []byte) {
	for i := 0; i < 16; i++ {
		state[i] = internal.InvSBOX[state[i]]
	}
}

// 行移位
func (a *AES) shiftRows(state []byte) {
	// 状态以列优先方式存储:
	// [ 0, 4, 8, 12,
	//   1, 5, 9, 13,
	//   2, 6, 10, 14,
	//   3, 7, 11, 15 ]

	// 第二行左移1位
	state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]

	// 第三行左移2位
	state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]

	// 第四行左移3位
	state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]
}

// 逆行移位
func (a *AES) invShiftRows(state []byte) {
	// 第二行右移1位
	state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]

	// 第三行右移2位
	state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]

	// 第四行右移3位
	state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]
}

// 列混合
func (a *AES) mixColumns(state []byte) {
	for i := 0; i < 4; i++ {
		// 获取当前列
		col := i * 4
		a0 := state[col]
		a1 := state[col+1]
		a2 := state[col+2]
		a3 := state[col+3]

		// 矩阵乘法
		state[col] = internal.MUL_2[a0] ^ internal.MUL_3[a1] ^ a2 ^ a3
		state[col+1] = a0 ^ internal.MUL_2[a1] ^ internal.MUL_3[a2] ^ a3
		state[col+2] = a0 ^ a1 ^ internal.MUL_2[a2] ^ internal.MUL_3[a3]
		state[col+3] = internal.MUL_3[a0] ^ a1 ^ a2 ^ internal.MUL_2[a3]
	}
}

// 逆列混合
func (a *AES) invMixColumns(state []byte) {
	for i := 0; i < 4; i++ {
		// 获取当前列
		col := i * 4
		a0 := state[col]
		a1 := state[col+1]
		a2 := state[col+2]
		a3 := state[col+3]

		// 矩阵乘法
		state[col] = internal.MUL_14[a0] ^ internal.MUL_11[a1] ^ internal.MUL_13[a2] ^ internal.MUL_9[a3]
		state[col+1] = internal.MUL_9[a0] ^ internal.MUL_14[a1] ^ internal.MUL_11[a2] ^ internal.MUL_13[a3]
		state[col+2] = internal.MUL_13[a0] ^ internal.MUL_9[a1] ^ internal.MUL_14[a2] ^ internal.MUL_11[a3]
		state[col+3] = internal.MUL_11[a0] ^ internal.MUL_13[a1] ^ internal.MUL_9[a2] ^ internal.MUL_14[a3]
	}
}

// 轮密钥加
func (a *AES) addRoundKey(state []byte, round int) {
	for i := 0; i < 4; i++ {
		k := a.roundKeys[round*4+i]
		col := i * 4

		// 将密钥与状态进行XOR操作
		state[col] ^= byte(k >> 24)
		state[col+1] ^= byte(k >> 16)
		state[col+2] ^= byte(k >> 8)
		state[col+3] ^= byte(k)
	}
}

// 辅助函数：字的循环左移
func rotWord(w uint32) uint32 {
	return (w << 8) | (w >> 24)
}

// 辅助函数：字的替代
func subWord(w uint32) uint32 {
	return uint32(internal.SBOX[byte(w>>24)])<<24 |
		uint32(internal.SBOX[byte(w>>16)])<<16 |
		uint32(internal.SBOX[byte(w>>8)])<<8 |
		uint32(internal.SBOX[byte(w)])
}

// BlockSize 返回AES的块大小（16字节）
func (a *AES) BlockSize() int {
	return 16
}
