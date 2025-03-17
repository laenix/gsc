package sm3

import (
	"encoding/binary"
	"hash"
	"math/bits"

	"github.com/laenix/gsc/sm3/internal"
)

// SM3算法常量
const (
	// 块大小（字节）
	BlockSize = 64
	// 摘要大小（字节）
	Size = 32
)

// SM3摘要算法结构体
type digest struct {
	h   [8]uint32       // 哈希值状态
	x   [BlockSize]byte // 当前块的缓冲区
	nx  int             // 缓冲区中的字节数
	len uint64          // 已处理的字节数
}

// 实现的接口检查
var _ hash.Hash = (*digest)(nil)

// New 创建新的SM3哈希实例
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// Reset 重置哈希状态
func (d *digest) Reset() {
	d.h = internal.IV // 使用初始值
	d.nx = 0
	d.len = 0
}

// Size 返回SM3哈希结果的字节长度
func (d *digest) Size() int {
	return Size
}

// BlockSize 返回SM3算法的块大小
func (d *digest) BlockSize() int {
	return BlockSize
}

// Write 向哈希计算中添加更多数据
func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)

	// 如果缓冲区中已有数据，先填满缓冲区并处理
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == BlockSize {
			d.block(d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}

	// 逐块处理完整的块
	if len(p) >= BlockSize {
		n := len(p) &^ (BlockSize - 1)
		d.block(p[:n])
		p = p[n:]
	}

	// 存储剩余数据到缓冲区
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}

	return nn, nil
}

// Sum 计算并返回当前数据的哈希值
func (d *digest) Sum(in []byte) []byte {
	// 克隆当前状态
	d0 := *d

	// 填充并计算最后的哈希值
	hash := d0.checkSum()

	// 将结果添加到提供的切片
	return append(in, hash[:]...)
}

// checkSum 添加填充并计算最终的哈希值
func (d *digest) checkSum() [Size]byte {
	// 创建填充后的最终结果
	len := d.len

	// 添加一个字节的1后跟多个0，以填充到最后的块
	// 填充规则：先添加一个1比特，然后添加k个0比特，使得 (len+1+k) mod 512 = 448
	// 这里对应的字节操作是添加0x80然后添加0填充
	var tmp [BlockSize]byte
	tmp[0] = 0x80

	// 计算填充的0的个数
	// 需要确保最后有8个字节用于存储长度
	padLen := BlockSize - ((int(len) + 1 + 8) % BlockSize)
	if padLen <= 0 {
		padLen += BlockSize
	}

	// 写入填充
	d.Write(tmp[:1+padLen])

	// 写入长度，大端序，长度以比特为单位
	// SM3使用比特长度的大端表示，占8字节
	len <<= 3 // 转换为比特长度
	binary.BigEndian.PutUint64(tmp[:8], len)
	d.Write(tmp[:8])

	// 确保所有数据都已处理
	if d.nx != 0 {
		panic("d.nx != 0")
	}

	// 将最终的哈希值作为字节数组返回
	var digest [Size]byte
	for i, v := range d.h {
		binary.BigEndian.PutUint32(digest[i*4:], v)
	}

	return digest
}

// block 处理一个完整的SM3数据块
func (d *digest) block(p []byte) {
	// 在此函数中实现SM3的核心压缩函数
	var w [68]uint32
	var w1 [64]uint32

	h0, h1, h2, h3, h4, h5, h6, h7 := d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7]

	for len(p) >= BlockSize {
		// 将消息分组扩展为132个字
		// 1. 将消息分组B划分为16个字W0, W1, ..., W15
		for i := 0; i < 16; i++ {
			j := i * 4
			w[i] = binary.BigEndian.Uint32(p[j:])
		}

		// 2. 按照规则生成W16, W17, ..., W67
		for i := 16; i < 68; i++ {
			w[i] = p1(w[i-16]^w[i-9]^bits.RotateLeft32(w[i-3], 15)) ^ bits.RotateLeft32(w[i-13], 7) ^ w[i-6]
		}

		// 3. 计算W'0, W'1, ..., W'63
		for i := 0; i < 64; i++ {
			w1[i] = w[i] ^ w[i+4]
		}

		// 压缩函数主循环
		a, b, c, d, e, f, g, h := h0, h1, h2, h3, h4, h5, h6, h7

		for j := 0; j < 64; j++ {
			ss1 := bits.RotateLeft32(bits.RotateLeft32(a, 12)+e+bits.RotateLeft32(internal.T[j], j), 7)
			ss2 := ss1 ^ bits.RotateLeft32(a, 12)
			tt1 := ff(a, b, c, j) + d + ss2 + w1[j]
			tt2 := gg(e, f, g, j) + h + ss1 + w[j]
			d = c
			c = bits.RotateLeft32(b, 9)
			b = a
			a = tt1
			h = g
			g = bits.RotateLeft32(f, 19)
			f = e
			e = p0(tt2)
		}

		// 更新哈希状态
		h0 ^= a
		h1 ^= b
		h2 ^= c
		h3 ^= d
		h4 ^= e
		h5 ^= f
		h6 ^= g
		h7 ^= h

		p = p[BlockSize:]
	}

	// 保存当前哈希状态
	d.h[0], d.h[1], d.h[2], d.h[3], d.h[4], d.h[5], d.h[6], d.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
}

// SM3算法中的置换函数ff
func ff(x, y, z uint32, j int) uint32 {
	if j <= 15 {
		return x ^ y ^ z // j=0~15
	}
	return (x & y) | (x & z) | (y & z) // j=16~63
}

// SM3算法中的置换函数gg
func gg(x, y, z uint32, j int) uint32 {
	if j <= 15 {
		return x ^ y ^ z // j=0~15
	}
	return (x & y) | ((^x) & z) // j=16~63
}

// SM3算法中的置换函数p0
func p0(x uint32) uint32 {
	return x ^ bits.RotateLeft32(x, 9) ^ bits.RotateLeft32(x, 17)
}

// SM3算法中的置换函数p1
func p1(x uint32) uint32 {
	return x ^ bits.RotateLeft32(x, 15) ^ bits.RotateLeft32(x, 23)
}

// Sum 计算数据的SM3哈希值
func Sum(data []byte) [Size]byte {
	var d digest
	d.Reset()
	d.Write(data)
	return d.checkSum()
}
