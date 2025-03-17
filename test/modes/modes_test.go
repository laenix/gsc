package modes_test

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/laenix/gsc/aes"
	"github.com/laenix/gsc/modes"
)

func TestCTR(t *testing.T) {
	// 示例密钥（16字节 = 128位）
	key := []byte("0123456789ABCDEF")

	// 创建AES密码
	cipher, err := aes.New(key)
	if err != nil {
		t.Fatalf("创建AES失败: %v", err)
	}

	// 示例明文
	plaintext := []byte("这是一个AES加密测试示例文本，用于测试CTR模式。")

	// 初始计数器（16字节）
	counter := []byte("1234567890123456")

	// 创建CTR模式
	ctr, err := modes.NewCTR(cipher, counter)
	if err != nil {
		t.Fatalf("创建CTR模式失败: %v", err)
	}

	// 加密
	ciphertext, err := ctr.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("CTR加密失败: %v", err)
	}

	// 重置CTR模式进行解密
	ctr, err = modes.NewCTR(cipher, counter)
	if err != nil {
		t.Fatalf("重置CTR模式失败: %v", err)
	}

	// 解密
	decrypted, err := ctr.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("CTR解密失败: %v", err)
	}

	// 验证明文和解密结果是否一致
	if string(plaintext) != string(decrypted) {
		t.Error("解密结果与原始明文不匹配!")
	}
}

func TestGCM(t *testing.T) {
	// 示例密钥（16字节 = 128位）
	key := []byte("0123456789ABCDEF")

	// 创建AES密码
	cipher, err := aes.New(key)
	if err != nil {
		t.Fatalf("创建AES失败: %v", err)
	}

	// 示例明文
	plaintext := []byte("这是一个AES加密测试示例文本，用于测试GCM模式。")

	// 随机生成的12字节Nonce
	nonce := []byte("123456789012")

	// 附加验证数据
	aad := []byte("附加验证数据")

	// 创建GCM模式
	gcm, err := modes.NewGCM(cipher)
	if err != nil {
		t.Fatalf("创建GCM模式失败: %v", err)
	}

	// 加密并计算认证标签
	ciphertext, err := gcm.Seal(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("GCM加密失败: %v", err)
	}

	// 解密并验证
	decrypted, err := gcm.Open(nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("GCM解密失败: %v", err)
	}

	// 验证明文和解密结果是否一致
	if string(plaintext) != string(decrypted) {
		t.Error("解密结果与原始明文不匹配!")
	}

	// 测试错误的附加数据
	wrongAAD := []byte("错误的附加数据")
	_, err = gcm.Open(nonce, ciphertext, wrongAAD)
	if err == nil {
		t.Error("应该检测到错误的附加数据!")
	}
}

func ExampleCTR() {
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

	// 加密
	ciphertext, err := ctr.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("CTR加密失败: %v", err)
	}
	fmt.Printf("CTR加密后的密文 (Hex): %s\n", hex.EncodeToString(ciphertext))

	// 重置CTR模式进行解密
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
}

func ExampleGCM() {
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

	// 随机生成的12字节Nonce
	nonce := []byte("123456789012")

	// 附加验证数据
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
}
