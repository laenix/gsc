package internal

// XORBytes 对两个字节数组按位异或
// 返回的结果长度为 min(len(a), len(b))
func XORBytes(dst, a, b []byte) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// Increment 将计数器加一
func Increment(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

// DuplicateSlice 复制切片
func DuplicateSlice(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
