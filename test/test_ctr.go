package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"gsc/aes"
	"gsc/modes"
)

func TestCTR() {
	// 示例密钥（16字节 = 128位）
	key := []byte("0123456789ABCDEF")

	// 创建AES密码
	cipher, err := aes.New(key)
	if err != nil {
		log.Fatalf("创建AES失败: %v", err)
	}

	// 示例明文
	plaintext := []byte("这是一个AES加密测试示例文本，用于测试CTR模式。")
	fmt.Printf("原始明文: %s\n\n", plaintext)

	// 初始计数器（16字节）
	counter := []byte("1234567890123456")

	// 创建CTR模式
	ctr, err := modes.NewCTR(cipher, counter)
	if err != nil {
		log.Fatalf("创建CTR模式失败: %v", err)
	}

	// 加密（CTR不需要填充）
	ciphertext, err := ctr.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("CTR加密失败: %v", err)
	}
	fmt.Printf("CTR加密后的密文 (Hex): %s\n", hex.EncodeToString(ciphertext))

	// 重置CTR模式（使用相同的计数器）进行解密
	ctr, err = modes.NewCTR(cipher, counter)
	if err != nil {
		log.Fatalf("重置CTR模式失败: %v", err)
	}

	// 解密
	decrypted, err := ctr.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("CTR解密失败: %v", err)
	}
	fmt.Printf("CTR解密后的明文: %s\n", decrypted)

	// 验证明文和解密结果是否一致
	if string(plaintext) != string(decrypted) {
		fmt.Println("错误: 解密结果与原始明文不匹配!")
	} else {
		fmt.Println("验证成功: 解密结果与原始明文匹配!")
	}
}
