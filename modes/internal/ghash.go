package internal

// GHASH 是GCM模式用于生成认证标签的哈希函数
type GHASH struct {
	// H是加密密钥后的值 E(0)
	h []byte
	// 预计算的GF(2^128)乘法表
	// 为简化，我们只实现基础版本，没有使用乘法表优化
}

// NewGHASH 创建一个新的GHASH实例
func NewGHASH(h []byte) *GHASH {
	hCopy := make([]byte, 16)
	copy(hCopy, h)
	return &GHASH{
		h: hCopy,
	}
}

// Update 更新GHASH状态
func (g *GHASH) Update(data []byte, y []byte) {
	// 确保数据是16字节的倍数（应该由调用者保证）
	for i := 0; i < len(data); i += 16 {
		// 将当前状态与数据块异或
		for j := 0; j < 16 && i+j < len(data); j++ {
			if i+j < len(data) {
				y[j] ^= data[i+j]
			}
		}
		// 在GF(2^128)上乘以H
		g.multiply(y)
	}
}

// multiply 在GF(2^128)上执行乘法 y = y * H
// 使用Horner方法计算
func (g *GHASH) multiply(y []byte) {
	// 使用简化的GF(2^128)乘法实现
	// 在实际生产代码中，应该使用更高效的算法和预计算表
	var z [16]byte
	var v [16]byte
	copy(v[:], g.h)

	for i := 0; i < 16; i++ {
		for j := uint(0); j < 8; j++ {
			if (y[i] & (1 << (7 - j))) != 0 {
				// 如果该位为1，则累加H的相应倍数
				for k := 0; k < 16; k++ {
					z[k] ^= v[k]
				}
			}
			// 计算下一个倍数 (v = v * x)
			bit := v[15] & 1
			shiftRight(&v)
			if bit == 1 {
				v[0] ^= 0xe1 // GF(2^128)多项式的低位系数
			}
		}
	}
	copy(y, z[:])
}

// shiftRight 将16字节数组向右移动1位
func shiftRight(v *[16]byte) {
	for i := 15; i > 0; i-- {
		v[i] = (v[i] >> 1) | (v[i-1] << 7)
	}
	v[0] >>= 1
}

// GMAC 计算给定数据的认证码
func GMAC(h, j0 []byte, aad, ciphertext []byte) []byte {
	// 初始化GHASH
	ghash := NewGHASH(h)

	// 初始化结果数组
	y := make([]byte, 16)

	// 处理额外认证数据 (AAD)
	if len(aad) > 0 {
		ghash.Update(aad, y)
		// 如果aad长度不是16的倍数，需要填充0
		padding := 16 - (len(aad) % 16)
		if padding < 16 {
			padBytes := make([]byte, padding)
			ghash.Update(padBytes, y)
		}
	}

	// 处理密文
	if len(ciphertext) > 0 {
		ghash.Update(ciphertext, y)
		// 如果密文长度不是16的倍数，需要填充0
		padding := 16 - (len(ciphertext) % 16)
		if padding < 16 {
			padBytes := make([]byte, padding)
			ghash.Update(padBytes, y)
		}
	}

	// 添加AAD和密文长度信息（以bit为单位，以big-endian格式存储）
	lengthBytes := make([]byte, 16)
	aadBits := uint64(len(aad) * 8)
	ciphertextBits := uint64(len(ciphertext) * 8)

	lengthBytes[0] = byte(aadBits >> 56)
	lengthBytes[1] = byte(aadBits >> 48)
	lengthBytes[2] = byte(aadBits >> 40)
	lengthBytes[3] = byte(aadBits >> 32)
	lengthBytes[4] = byte(aadBits >> 24)
	lengthBytes[5] = byte(aadBits >> 16)
	lengthBytes[6] = byte(aadBits >> 8)
	lengthBytes[7] = byte(aadBits)

	lengthBytes[8] = byte(ciphertextBits >> 56)
	lengthBytes[9] = byte(ciphertextBits >> 48)
	lengthBytes[10] = byte(ciphertextBits >> 40)
	lengthBytes[11] = byte(ciphertextBits >> 32)
	lengthBytes[12] = byte(ciphertextBits >> 24)
	lengthBytes[13] = byte(ciphertextBits >> 16)
	lengthBytes[14] = byte(ciphertextBits >> 8)
	lengthBytes[15] = byte(ciphertextBits)

	ghash.Update(lengthBytes, y)

	// 最后与J0异或得到认证标签
	tag := make([]byte, 16)
	XORBytes(tag, y, j0)

	return tag
}
