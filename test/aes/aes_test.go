package aes_test

import (
	"bytes"
	"fmt"
	"testing"

	"gsc/aes"
	"gsc/padding"
)

func TestAES(t *testing.T) {
	// 创建密钥（16字节）
	key := []byte("0123456789ABCDEF")

	// 创建明文（需要填充）
	plaintext := []byte("测试AES加密解密")
	fmt.Printf("原始明文长度: %d\n", len(plaintext))

	// 使用PKCS7填充
	paddedPlaintext := padding.PKCS7Padding(plaintext, 16)
	fmt.Printf("填充后明文长度: %d\n", len(paddedPlaintext))

	// 创建AES加密器
	cipher, err := aes.New(key)
	if err != nil {
		t.Fatalf("创建AES加密器失败: %v", err)
	}

	// 分块加密
	blockSize := 16
	ciphertext := make([]byte, len(paddedPlaintext))
	for i := 0; i < len(paddedPlaintext); i += blockSize {
		block, err := cipher.Encrypt(paddedPlaintext[i : i+blockSize])
		if err != nil {
			t.Fatalf("AES加密失败: %v", err)
		}
		copy(ciphertext[i:i+blockSize], block)
	}

	// 分块解密
	decryptedText := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		block, err := cipher.Decrypt(ciphertext[i : i+blockSize])
		if err != nil {
			t.Fatalf("AES解密失败: %v", err)
		}
		copy(decryptedText[i:i+blockSize], block)
	}

	// 移除填充
	unpaddedText, err := padding.PKCS7Unpadding(decryptedText)
	if err != nil {
		t.Fatalf("移除填充失败: %v", err)
	}

	// 验证结果
	if !bytes.Equal(plaintext, unpaddedText) {
		t.Errorf("解密结果与原文不匹配\n原文: %v\n解密: %v", plaintext, unpaddedText)
	} else {
		fmt.Printf("测试成功！\n原文: %s\n解密: %s\n", plaintext, unpaddedText)
	}
}

func ExampleAES() {
	// 创建密钥（16字节）
	key := []byte("0123456789ABCDEF")

	// 创建明文（需要填充）
	plaintext := []byte("测试AES加密解密")

	// 使用PKCS7填充
	paddedPlaintext := padding.PKCS7Padding(plaintext, 16)

	// 创建AES加密器
	cipher, _ := aes.New(key)

	// 分块加密
	blockSize := 16
	ciphertext := make([]byte, len(paddedPlaintext))
	for i := 0; i < len(paddedPlaintext); i += blockSize {
		block, _ := cipher.Encrypt(paddedPlaintext[i : i+blockSize])
		copy(ciphertext[i:i+blockSize], block)
	}

	// 分块解密
	decryptedText := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		block, _ := cipher.Decrypt(ciphertext[i : i+blockSize])
		copy(decryptedText[i:i+blockSize], block)
	}

	// 移除填充
	unpaddedText, _ := padding.PKCS7Unpadding(decryptedText)

	// 输出结果
	fmt.Printf("原文: %s\n", plaintext)
	fmt.Printf("解密: %s\n", unpaddedText)
}
