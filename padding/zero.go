package padding

import "bytes"

// ZeroPadding 使用零字节填充
func ZeroPadding(data []byte, blockSize int) []byte {
	// 计算需要填充的字节数
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}

	// 创建填充字节切片
	padtext := bytes.Repeat([]byte{0}, padding)

	// 将填充添加到原始数据
	return append(data, padtext...)
}

// ZeroUnpadding 移除零字节填充
func ZeroUnpadding(data []byte) []byte {
	// 从末尾开始查找第一个非零字节
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] != 0 {
			return data[:i+1]
		}
	}
	return []byte{}
}
