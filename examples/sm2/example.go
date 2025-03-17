package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/laenix/gsc/sm2"
)

func main() {
	// 创建SM2实例
	sm2Instance := sm2.New()

	// 生成密钥对
	privateKey, err := sm2Instance.GenerateKey(nil)
	if err != nil {
		log.Fatalf("生成密钥对失败: %v", err)
	}

	// 显示密钥对
	fmt.Println("密钥对生成成功:")
	fmt.Printf("私钥: %s\n", hex.EncodeToString(privateKey.EncodePrivateKey()))
	fmt.Printf("公钥: %s\n", hex.EncodeToString(privateKey.PublicKey.EncodePublicKey()))

	// 测试加密和解密
	plaintext := []byte("Hello, SM2加密!")
	fmt.Printf("\n原始明文: %s\n", plaintext)

	// 加密
	ciphertext, err := sm2Instance.Encrypt(&privateKey.PublicKey, plaintext, nil)
	if err != nil {
		log.Fatalf("加密失败: %v", err)
	}
	fmt.Printf("密文: %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err := sm2Instance.Decrypt(privateKey, ciphertext)
	if err != nil {
		log.Fatalf("解密失败: %v", err)
	}
	fmt.Printf("解密后明文: %s\n", decrypted)

	// 测试签名和验证
	message := []byte("需要签名的信息")
	fmt.Printf("\n待签名消息: %s\n", message)

	// 使用用户标识符签名
	uid := []byte("1234567812345678")
	signature, err := sm2Instance.SignWithId(privateKey, message, uid)
	if err != nil {
		log.Fatalf("签名失败: %v", err)
	}
	fmt.Printf("签名结果: %s\n", hex.EncodeToString(signature))

	// 验证签名
	valid := sm2Instance.VerifyWithId(&privateKey.PublicKey, message, signature, uid)
	fmt.Printf("签名验证结果: %v\n", valid)

	// 验证错误的消息
	wrongMessage := []byte("错误的消息")
	valid = sm2Instance.VerifyWithId(&privateKey.PublicKey, wrongMessage, signature, uid)
	fmt.Printf("错误消息的验证结果: %v\n", valid)
}
