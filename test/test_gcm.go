package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"gsc/aes"
	"gsc/modes"
)

func TestGCM() {
	// 示例密钥（16字节 = 128位）
	key := []byte("0123456789ABCDEF")

	// 创建AES密码
	cipher, err := aes.New(key)
	if err != nil {
		log.Fatalf("创建AES失败: %v", err)
	}

	// 示例明文
	plaintext := []byte("这是一个AES加密测试示例文本，用于测试GCM模式。")
	fmt.Printf("原始明文: %s\n\n", plaintext)

	// 随机生成的12字节Nonce（在实际应用中应该是随机的）
	nonce := []byte("123456789012")

	// 附加验证数据（可选）
	aad := []byte("附加验证数据")

	// 创建GCM模式
	gcm, err := modes.NewGCM(cipher)
	if err != nil {
		log.Fatalf("创建GCM模式失败: %v", err)
	}

	// 加密并计算认证标签
	ciphertext, err := gcm.Seal(nonce, plaintext, aad)
	if err != nil {
		log.Fatalf("GCM加密失败: %v", err)
	}
	fmt.Printf("GCM加密后的密文 (Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密并验证
	decrypted, err := gcm.Open(nonce, ciphertext, aad)
	if err != nil {
		log.Fatalf("GCM解密失败: %v", err)
	}
	fmt.Printf("GCM解密后的明文: %s\n", decrypted)

	// 验证明文和解密结果是否一致
	if string(plaintext) != string(decrypted) {
		fmt.Println("错误: 解密结果与原始明文不匹配!")
	} else {
		fmt.Println("验证成功: 解密结果与原始明文匹配!")
	}

	// 测试错误的附加数据
	wrongAAD := []byte("错误的附加数据")
	_, err = gcm.Open(nonce, ciphertext, wrongAAD)
	if err != nil {
		fmt.Printf("预期的错误（错误附加数据）: %v\n", err)
	} else {
		fmt.Println("错误: 应该检测到错误的附加数据!")
	}
}
