package padding

import "bytes"

// PKCS7Padding 使用PKCS#7标准对数据进行填充
// 填充的字节值等于填充的字节数
func PKCS7Padding(data []byte, blockSize int) []byte {
	// 计算需要填充的字节数
	padding := blockSize - (len(data) % blockSize)
	if padding == 0 {
		padding = blockSize
	}

	// 创建填充字节切片
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)

	// 将填充添加到原始数据
	return append(data, padtext...)
}

// PKCS7Unpadding 移除PKCS#7填充
func PKCS7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, ErrInvalidPadding
	}

	// 获取填充的字节数（最后一个字节的值）
	padding := int(data[length-1])

	// 验证填充是否有效
	if padding > length {
		return nil, ErrInvalidPadding
	}

	// 检查所有填充字节是否一致
	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, ErrInvalidPadding
		}
	}

	// 返回去除填充后的数据
	return data[:length-padding], nil
}
