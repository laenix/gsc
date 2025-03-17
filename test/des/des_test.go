package des_test

import (
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/laenix/gsc/des"
	"github.com/laenix/gsc/padding"
)

func TestDES(t *testing.T) {
	// 示例密钥（8字节 = 64位）
	key := []byte("12345678")

	// 创建DES密码
	cipher, err := des.New(key)
	if err != nil {
		t.Fatalf("创建DES失败: %v", err)
	}

	// 示例明文
	plaintext := []byte("DESTEST")

	// 对明文进行PKCS#7填充
	paddedPlaintext := padding.PKCS7Padding(plaintext, cipher.BlockSize())

	// 加密
	ciphertext, err := cipher.Encrypt(paddedPlaintext)
	if err != nil {
		t.Fatalf("DES加密失败: %v", err)
	}

	// 解密
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("DES解密失败: %v", err)
	}

	// 去除填充
	unpaddedDecrypted, err := padding.PKCS7Unpadding(decrypted)
	if err != nil {
		t.Fatalf("去除填充失败: %v", err)
	}

	// 验证明文和解密结果是否一致
	if string(plaintext) != string(unpaddedDecrypted) {
		t.Error("解密结果与原始明文不匹配!")
	}
}

func ExampleDES() {
	// 示例密钥（8字节 = 64位）
	key := []byte("12345678")

	// 创建DES密码
	cipher, err := des.New(key)
	if err != nil {
		log.Fatalf("创建DES失败: %v", err)
	}

	// 示例明文
	plaintext := []byte("DESTEST")
	fmt.Printf("原始明文: %s\n", plaintext)
	fmt.Printf("明文长度: %d 字节\n", len(plaintext))
	fmt.Printf("明文十六进制: %s\n\n", hex.EncodeToString(plaintext))

	// 对明文进行PKCS#7填充
	paddedPlaintext := padding.PKCS7Padding(plaintext, cipher.BlockSize())
	fmt.Printf("填充后明文长度: %d 字节\n", len(paddedPlaintext))
	fmt.Printf("填充后明文十六进制: %s\n\n", hex.EncodeToString(paddedPlaintext))

	// 加密
	ciphertext, err := cipher.Encrypt(paddedPlaintext)
	if err != nil {
		log.Fatalf("DES加密失败: %v", err)
	}
	fmt.Printf("DES加密后的密文 (Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("DES解密失败: %v", err)
	}
	fmt.Printf("DES解密后的填充明文: %s\n", decrypted)
	fmt.Printf("解密后填充明文十六进制: %s\n\n", hex.EncodeToString(decrypted))

	// 去除填充
	unpaddedDecrypted, err := padding.PKCS7Unpadding(decrypted)
	if err != nil {
		log.Fatalf("去除填充失败: %v", err)
	}
	fmt.Printf("去除填充后的明文: %s\n", unpaddedDecrypted)
}
