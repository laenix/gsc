package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"gsc/aes"
	"gsc/modes"
)

func main() {
	// 示例密钥（16字节 = 128位）
	key := []byte("0123456789ABCDEF")

	// 创建AES密码
	cipher, err := aes.New(key)
	if err != nil {
		log.Fatalf("创建AES失败: %v", err)
	}

	// 示例明文
	plaintext := []byte("这是一个AES加密测试示例文本，用于展示不同的加密模式。")
	fmt.Printf("原始明文: %s\n\n", plaintext)

	// 1. ECB模式示例
	fmt.Println("=== ECB模式示例 ===")
	demonstrateECB(cipher, plaintext)

	// 2. CBC模式示例
	fmt.Println("\n=== CBC模式示例 ===")
	demonstrateCBC(cipher, plaintext)

	// 3. CFB模式示例
	fmt.Println("\n=== CFB模式示例 ===")
	demonstrateCFB(cipher, plaintext)

	// 4. OFB模式示例
	fmt.Println("\n=== OFB模式示例 ===")
	demonstrateOFB(cipher, plaintext)

	// CTR和GCM模式需要更多调试，此版本中暂不包含
}

// ECB模式示例
func demonstrateECB(cipher modes.BlockCipher, plaintext []byte) {
	// 创建ECB模式
	ecb := modes.NewECB(cipher)

	// 使用PKCS7填充进行加密
	ciphertext, err := ecb.EncryptPadded(plaintext)
	if err != nil {
		log.Fatalf("ECB加密失败: %v", err)
	}
	fmt.Printf("ECB加密后的密文 (Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密并移除填充
	decrypted, err := ecb.DecryptPadded(ciphertext)
	if err != nil {
		log.Fatalf("ECB解密失败: %v", err)
	}
	fmt.Printf("ECB解密后的明文: %s\n", decrypted)
}

// CBC模式示例
func demonstrateCBC(cipher modes.BlockCipher, plaintext []byte) {
	// 初始化向量 (IV)
	iv := []byte("InitializVector.")

	// 创建CBC模式
	cbc, err := modes.NewCBC(cipher, iv)
	if err != nil {
		log.Fatalf("创建CBC模式失败: %v", err)
	}

	// 使用PKCS7填充进行加密
	ciphertext, err := cbc.EncryptPadded(plaintext)
	if err != nil {
		log.Fatalf("CBC加密失败: %v", err)
	}
	fmt.Printf("CBC加密后的密文 (Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密并移除填充
	decrypted, err := cbc.DecryptPadded(ciphertext)
	if err != nil {
		log.Fatalf("CBC解密失败: %v", err)
	}
	fmt.Printf("CBC解密后的明文: %s\n", decrypted)
}

// CFB模式示例
func demonstrateCFB(cipher modes.BlockCipher, plaintext []byte) {
	// 初始化向量 (IV)
	iv := []byte("InitializVector.")

	// 创建CFB模式
	cfb, err := modes.NewCFB(cipher, iv)
	if err != nil {
		log.Fatalf("创建CFB模式失败: %v", err)
	}

	// 加密（CFB不需要填充）
	ciphertext, err := cfb.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("CFB加密失败: %v", err)
	}
	fmt.Printf("CFB加密后的密文 (Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err := cfb.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("CFB解密失败: %v", err)
	}
	fmt.Printf("CFB解密后的明文: %s\n", decrypted)
}

// OFB模式示例
func demonstrateOFB(cipher modes.BlockCipher, plaintext []byte) {
	// 初始化向量 (IV)
	iv := []byte("InitializVector.")

	// 创建OFB模式
	ofb, err := modes.NewOFB(cipher, iv)
	if err != nil {
		log.Fatalf("创建OFB模式失败: %v", err)
	}

	// 加密（OFB不需要填充）
	ciphertext, err := ofb.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("OFB加密失败: %v", err)
	}
	fmt.Printf("OFB加密后的密文 (Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err := ofb.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("OFB解密失败: %v", err)
	}
	fmt.Printf("OFB解密后的明文: %s\n", decrypted)
}
