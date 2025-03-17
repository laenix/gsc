package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/laenix/gsc/rc5"
)

func main() {
	// 示例密钥 - 16字节 (128位)
	key := []byte("0123456789abcdef")

	// 创建新的RC5实例，使用默认参数 (RC5-32/12/16)
	cipher, err := rc5.New(key)
	if err != nil {
		log.Fatalf("创建RC5实例失败: %v", err)
	}

	// 明文数据 (8字节)
	plaintext := []byte("Hello RC5")[:8]
	fmt.Printf("明文 (hex): %s\n", hex.EncodeToString(plaintext))

	// 加密
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}
	fmt.Printf("密文 (hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("解密失败: %v", err)
	}
	fmt.Printf("解密后 (hex): %s\n", hex.EncodeToString(decrypted))
	fmt.Printf("解密后 (text): %s\n", string(decrypted))

	// 使用自定义参数的示例
	fmt.Println("\n自定义参数示例 (RC5-32/16/24):")

	// 使用24字节密钥和16轮
	longKey := []byte("0123456789abcdefghijklmn")
	customCipher, err := rc5.NewWithParams(longKey, 16, 32)
	if err != nil {
		log.Fatalf("创建自定义RC5实例失败: %v", err)
	}

	// 加密和解密
	customCiphertext, err := customCipher.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("自定义加密失败: %v", err)
	}
	fmt.Printf("自定义密文 (hex): %s\n", hex.EncodeToString(customCiphertext))

	customDecrypted, err := customCipher.Decrypt(customCiphertext)
	if err != nil {
		log.Fatalf("自定义解密失败: %v", err)
	}
	fmt.Printf("自定义解密后 (hex): %s\n", hex.EncodeToString(customDecrypted))
	fmt.Printf("自定义解密后 (text): %s\n", string(customDecrypted))
}
