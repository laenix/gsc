package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/laenix/gsc/modes"
	"github.com/laenix/gsc/padding"
	"github.com/laenix/gsc/sm4"
)

func main() {
	// 创建一个16字节的密钥
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext := []byte("这是SM4加密算法的测试文本，长度超过一个块。")

	// 创建SM4实例
	cipher, err := sm4.New(key)
	if err != nil {
		log.Fatalf("创建SM4实例失败: %v", err)
	}

	fmt.Println("【基本信息】")
	fmt.Printf("算法: SM4\n")
	fmt.Printf("密钥: %x\n", key)
	fmt.Printf("明文: %s\n", plaintext)
	fmt.Printf("明文(Hex): %x\n", plaintext)
	fmt.Println()

	// ECB模式示例
	fmt.Println("【ECB模式】")
	ecb := modes.NewECB(cipher)

	// 使用PKCS7填充
	paddedPlaintext, _ := padding.PKCS7Padding(plaintext, cipher.BlockSize())
	ecbCiphertext, err := ecb.Encrypt(paddedPlaintext)
	if err != nil {
		log.Fatalf("ECB加密失败: %v", err)
	}
	fmt.Printf("密文(Hex): %x\n", ecbCiphertext)

	// ECB解密
	ecbDecrypted, err := ecb.Decrypt(ecbCiphertext)
	if err != nil {
		log.Fatalf("ECB解密失败: %v", err)
	}
	ecbDecrypted, err = padding.PKCS7UnPadding(ecbDecrypted)
	if err != nil {
		log.Fatalf("解除PKCS7填充失败: %v", err)
	}
	fmt.Printf("解密(Hex): %x\n", ecbDecrypted)
	fmt.Printf("解密: %s\n", ecbDecrypted)
	fmt.Println()

	// CBC模式示例
	fmt.Println("【CBC模式】")
	iv := []byte("1234567890123456")
	fmt.Printf("IV: %x\n", iv)

	cbc, err := modes.NewCBC(cipher, iv)
	if err != nil {
		log.Fatalf("创建CBC模式失败: %v", err)
	}

	paddedPlaintext, _ = padding.PKCS7Padding(plaintext, cipher.BlockSize())
	cbcCiphertext, err := cbc.Encrypt(paddedPlaintext)
	if err != nil {
		log.Fatalf("CBC加密失败: %v", err)
	}
	fmt.Printf("密文(Hex): %x\n", cbcCiphertext)

	// CBC解密
	cbcDecrypted, err := cbc.Decrypt(cbcCiphertext)
	if err != nil {
		log.Fatalf("CBC解密失败: %v", err)
	}
	cbcDecrypted, err = padding.PKCS7UnPadding(cbcDecrypted)
	if err != nil {
		log.Fatalf("解除PKCS7填充失败: %v", err)
	}
	fmt.Printf("解密(Hex): %x\n", cbcDecrypted)
	fmt.Printf("解密: %s\n", cbcDecrypted)
	fmt.Println()

	// CTR模式示例
	fmt.Println("【CTR模式】")
	counter := []byte("1234567890123456")
	fmt.Printf("计数器: %x\n", counter)

	ctr, err := modes.NewCTR(cipher, counter)
	if err != nil {
		log.Fatalf("创建CTR模式失败: %v", err)
	}

	ctrCiphertext, err := ctr.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("CTR加密失败: %v", err)
	}
	fmt.Printf("密文(Hex): %x\n", ctrCiphertext)

	// CTR解密（实际上是再次加密）
	ctr, err = modes.NewCTR(cipher, counter) // 需要重置计数器
	if err != nil {
		log.Fatalf("重置CTR模式失败: %v", err)
	}

	ctrDecrypted, err := ctr.Decrypt(ctrCiphertext)
	if err != nil {
		log.Fatalf("CTR解密失败: %v", err)
	}
	fmt.Printf("解密(Hex): %x\n", ctrDecrypted)
	fmt.Printf("解密: %s\n", ctrDecrypted)
}
