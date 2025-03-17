package internal

// SM3常量定义

// 初始哈希值（IV）
var IV = [8]uint32{
	0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
	0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
}

// 常量T_j
// T_j = 0x79cc4519 当 0 ≤ j ≤ 15
// T_j = 0x7a879d8a 当 16 ≤ j ≤ 63
var T = [64]uint32{}

func init() {
	// 初始化常量T
	for i := 0; i < 16; i++ {
		T[i] = 0x79CC4519
	}
	for i := 16; i < 64; i++ {
		T[i] = 0x7A879D8A
	}
}
