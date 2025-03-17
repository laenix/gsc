package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/laenix/gsc/rc4"
)

func main() {
	// 示例密钥
	key := []byte("这是一个RC4密钥")

	// 示例明文
	plaintext := []byte("这是需要加密的明文消息")
	fmt.Printf("原始明文: %s\n", plaintext)

	// 创建RC4实例
	cipher, err := rc4.New(key)
	if err != nil {
		log.Fatalf("创建RC4失败: %v", err)
	}

	// 加密数据
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}
	fmt.Printf("加密后的密文 (十六进制): %s\n", hex.EncodeToString(ciphertext))

	// 创建新的RC4实例用于解密
	// 注意: RC4是流密码，需要从头开始，因此需要重新初始化
	decipher, err := rc4.New(key)
	if err != nil {
		log.Fatalf("创建RC4失败: %v", err)
	}

	// 解密数据
	decrypted, err := decipher.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("解密失败: %v", err)
	}
	fmt.Printf("解密后的明文: %s\n", decrypted)

	// 使用Reset方法重置RC4实例
	cipher.Reset(key)

	// 再次加密，应该得到相同的结果
	newCiphertext, _ := cipher.Encrypt(plaintext)
	fmt.Printf("重置后再次加密得到的密文 (十六进制): %s\n", hex.EncodeToString(newCiphertext))

	// 验证两次加密结果是否相同
	fmt.Printf("两次加密结果是否相同: %v\n", hex.EncodeToString(ciphertext) == hex.EncodeToString(newCiphertext))
}
