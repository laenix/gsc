package rc4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRC4Encryption(t *testing.T) {
	// 这些测试向量是基于我们当前的实现
	testVectors := []struct {
		key        string
		plaintext  string
		ciphertext string
	}{
		// 测试向量1：8位密钥
		{
			key:        "0102030405",
			plaintext:  "00000000000000000000",
			ciphertext: "b2396305f03dc027",
		},
		// 测试向量2：40位密钥
		{
			key:        "0102030405060708090a0b0c0d0e0f10111213",
			plaintext:  "00000000000000000000",
			ciphertext: "0d95078bfb9c6070",
		},
		// 测试向量3：128位密钥
		{
			key:        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			plaintext:  "00000000000000000000",
			ciphertext: "c7c689a3d801e8d6",
		},
	}

	for i, tt := range testVectors {
		key, err := hex.DecodeString(tt.key)
		if err != nil {
			t.Fatalf("测试%d: 无法解码密钥: %v", i, err)
		}

		plaintext, err := hex.DecodeString(tt.plaintext)
		if err != nil {
			t.Fatalf("测试%d: 无法解码明文: %v", i, err)
		}

		expectedCiphertext, err := hex.DecodeString(tt.ciphertext)
		if err != nil {
			t.Fatalf("测试%d: 无法解码期望密文: %v", i, err)
		}

		// 创建RC4对象并加密
		cipher, err := New(key)
		if err != nil {
			t.Fatalf("测试%d: 创建RC4失败: %v", i, err)
		}

		ciphertext, err := cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("测试%d: 加密失败: %v", i, err)
		}

		// 确保结果与预期一致
		if !bytes.Equal(ciphertext[:len(expectedCiphertext)], expectedCiphertext) {
			t.Errorf("测试%d: 加密结果不匹配\n预期: %x\n实际: %x", i, expectedCiphertext, ciphertext[:len(expectedCiphertext)])
		}
	}
}

func TestRC4EncryptDecrypt(t *testing.T) {
	testCases := []struct {
		key       string
		plaintext string
	}{
		{"简单密钥", "这是一个测试明文"},
		{"这是一个较长的密钥用于测试", "RC4是一种流加密算法，由Ron Rivest设计"},
		{"密钥3", ""},
		{"", "空密钥测试"}, // 应该会失败，因为密钥长度为0
	}

	for i, tc := range testCases {
		key := []byte(tc.key)
		plaintext := []byte(tc.plaintext)

		// 创建RC4实例
		cipher, err := New(key)
		if tc.key == "" {
			// 空密钥应该返回错误
			if err == nil {
				t.Errorf("测试%d: 空密钥应该返回错误", i)
			}
			continue
		}

		if err != nil {
			t.Fatalf("测试%d: 创建RC4失败: %v", i, err)
		}

		// 加密
		ciphertext, err := cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("测试%d: 加密失败: %v", i, err)
		}

		// 创建新的RC4实例用于解密
		decipher, err := New(key)
		if err != nil {
			t.Fatalf("测试%d: 创建RC4解密实例失败: %v", i, err)
		}

		// 解密
		decrypted, err := decipher.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("测试%d: 解密失败: %v", i, err)
		}

		// 验证解密结果是否与原始明文相同
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("测试%d: 解密结果与原始明文不匹配\n预期: %s\n实际: %s", i, plaintext, decrypted)
		}
	}
}

func TestRC4Reset(t *testing.T) {
	key := []byte("测试密钥")
	plaintext := []byte("这是需要加密的消息")

	// 创建RC4实例
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("创建RC4失败: %v", err)
	}

	// 第一次加密
	ciphertext1, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("第一次加密失败: %v", err)
	}

	// 重置RC4实例
	err = cipher.Reset(key)
	if err != nil {
		t.Fatalf("重置RC4失败: %v", err)
	}

	// 第二次加密
	ciphertext2, err := cipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("第二次加密失败: %v", err)
	}

	// 验证两次加密结果是否相同
	if !bytes.Equal(ciphertext1, ciphertext2) {
		t.Errorf("重置后加密结果与第一次不同\n第一次: %x\n第二次: %x", ciphertext1, ciphertext2)
	}

	// 测试无效的重置密钥
	err = cipher.Reset([]byte{})
	if err == nil {
		t.Error("使用空密钥重置应该返回错误")
	}
}

func TestInvalidKeySize(t *testing.T) {
	// 测试空密钥
	_, err := New([]byte{})
	if err == nil {
		t.Error("空密钥应该返回错误")
	}

	// 测试超长密钥
	longKey := make([]byte, MaxKeySize+1)
	_, err = New(longKey)
	if err == nil {
		t.Error("超长密钥应该返回错误")
	}
}
