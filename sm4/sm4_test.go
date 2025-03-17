package sm4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// 测试加密和解密的正确性
func TestEncryptDecrypt(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")

	// 创建SM4实例
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("创建SM4实例失败: %v", err)
	}

	// 加密
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 解密
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	// 验证解密结果与原文是否相同
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("加解密结果不匹配:\n原文: %x\n解密: %x", plaintext, decrypted)
	}
}

// 使用已知答案测试
func TestVectors(t *testing.T) {
	// 测试向量 1
	key1, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintext1, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	expected1, _ := hex.DecodeString("681EDF34D206965E86B3E94F536E4246")

	cipher1, _ := New(key1)
	ciphertext1, _ := cipher1.Encrypt(plaintext1)

	if !bytes.Equal(ciphertext1, expected1) {
		t.Errorf("测试向量1 加密结果不匹配:\n期望值: %x\n实际值: %x", expected1, ciphertext1)
	}

	// 测试向量 2
	key2, _ := hex.DecodeString("FEDCBA98765432100123456789ABCDEF")
	plaintext2, _ := hex.DecodeString("FEDCBA98765432100123456789ABCDEF")
	expected2, _ := hex.DecodeString("9CAD22E0676AB60CEDE9CFADC30B3D89")

	cipher2, _ := New(key2)
	ciphertext2, _ := cipher2.Encrypt(plaintext2)

	if !bytes.Equal(ciphertext2, expected2) {
		t.Errorf("测试向量2 加密结果不匹配:\n期望值: %x\n实际值: %x", expected2, ciphertext2)
	}
}

// 测试不正确的输入
func TestInvalidInput(t *testing.T) {
	// 测试无效密钥长度
	_, err := New([]byte{1, 2, 3})
	if err == nil {
		t.Error("应该对无效长度密钥报错")
	}

	// 测试有效密钥
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	cipher, _ := New(key)

	// 测试无效块大小
	_, err = cipher.Encrypt([]byte{1, 2, 3})
	if err == nil {
		t.Error("应该对无效长度块报错")
	}

	_, err = cipher.Decrypt([]byte{1, 2, 3})
	if err == nil {
		t.Error("应该对无效长度块报错")
	}
}

// 测试多个块的连续加解密
func TestMultipleBlocks(t *testing.T) {
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	plaintexts := [][]byte{
		make([]byte, 16),
		bytes.Repeat([]byte{0x01}, 16),
		bytes.Repeat([]byte{0x02}, 16),
	}

	cipher, _ := New(key)

	for i, pt := range plaintexts {
		// 加密
		ct, err := cipher.Encrypt(pt)
		if err != nil {
			t.Fatalf("块 %d 加密失败: %v", i, err)
		}

		// 解密
		dt, err := cipher.Decrypt(ct)
		if err != nil {
			t.Fatalf("块 %d 解密失败: %v", i, err)
		}

		// 验证
		if !bytes.Equal(pt, dt) {
			t.Errorf("块 %d 加解密结果不匹配:\n原文: %x\n解密: %x", i, pt, dt)
		}
	}
}
