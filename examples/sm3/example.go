package main

import (
	"encoding/hex"
	"fmt"

	"github.com/laenix/gsc/sm3"
)

// SM3Example 展示SM3哈希算法的使用方法
func main() {
	// 示例1：简单字符串哈希
	data := []byte("abc")
	hash := sm3.Sum(data)
	fmt.Printf("SM3('abc') = %s\n", hex.EncodeToString(hash[:]))

	// 示例2：使用hash.Hash接口
	h := sm3.New()
	h.Write([]byte("abcd"))
	h.Write([]byte("efgh"))
	sum := h.Sum(nil)
	fmt.Printf("SM3('abcdefgh') = %s\n", hex.EncodeToString(sum))

	// 示例3：重用哈希实例
	h.Reset()
	h.Write([]byte("测试中文输入"))
	sum = h.Sum(nil)
	fmt.Printf("SM3('测试中文输入') = %s\n", hex.EncodeToString(sum))

	// 示例4：空字符串哈希
	h.Reset()
	sum = h.Sum(nil)
	fmt.Printf("SM3('') = %s\n", hex.EncodeToString(sum))

	// 示例5：长文本哈希
	longText := make([]byte, 10000)
	for i := range longText {
		longText[i] = byte(i % 256)
	}
	hash = sm3.Sum(longText)
	fmt.Printf("SM3(长文本) = %s\n", hex.EncodeToString(hash[:]))
}
