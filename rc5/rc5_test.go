package rc5

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRc5EncryptDecrypt(t *testing.T) {
	// 测试用例
	testCases := []struct {
		name      string
		key       []byte
		plaintext []byte
		rounds    int
		wordSize  int
	}{
		{
			name:      "标准RC5-32/12/16",
			key:       []byte("0123456789abcdef"),
			plaintext: []byte("abcdefgh"),
			rounds:    12,
			wordSize:  32,
		},
		{
			name:      "RC5-32/8/8",
			key:       []byte("01234567"),
			plaintext: []byte("12345678"),
			rounds:    8,
			wordSize:  32,
		},
		{
			name:      "RC5-32/16/24",
			key:       []byte("0123456789abcdefghijklmn"),
			plaintext: []byte("HelloRC5"),
			rounds:    16,
			wordSize:  32,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 创建RC5实例
			cipher, err := NewWithParams(tc.key, tc.rounds, tc.wordSize)
			if err != nil {
				t.Fatalf("创建RC5实例失败: %v", err)
			}

			// 确保明文长度为BlockSize
			plaintext := make([]byte, cipher.BlockSize())
			copy(plaintext, tc.plaintext)

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

			// 验证解密后的明文是否与原始明文匹配
			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("解密结果不匹配\n原始明文: %s\n解密结果: %s",
					hex.EncodeToString(plaintext), hex.EncodeToString(decrypted))
			}
		})
	}
}

func TestRc5InvalidParameters(t *testing.T) {
	// 测试无效密钥长度
	_, err := New([]byte{})
	if err != ErrInvalidKeySize {
		t.Errorf("对于空密钥，预期 ErrInvalidKeySize，但得到：%v", err)
	}

	// 测试溢出密钥长度
	longKey := make([]byte, MaxKeySize+1)
	_, err = New(longKey)
	if err != ErrInvalidKeySize {
		t.Errorf("对于过长密钥，预期 ErrInvalidKeySize，但得到：%v", err)
	}

	// 测试无效轮数
	key := []byte("0123456789abcdef")
	_, err = NewWithParams(key, 0, 32)
	if err != ErrInvalidRounds {
		t.Errorf("对于轮数0，预期 ErrInvalidRounds，但得到：%v", err)
	}

	// 测试无效字长
	_, err = NewWithParams(key, 12, 16)
	if err != ErrInvalidWordSize {
		t.Errorf("对于非标准字长，预期 ErrInvalidWordSize，但得到：%v", err)
	}

	// 测试有效参数
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("创建有效的RC5实例失败：%v", err)
	}

	// 测试无效块大小
	_, err = cipher.Encrypt([]byte("short"))
	if err != ErrInvalidBlockSize {
		t.Errorf("对于短块，预期 ErrInvalidBlockSize，但得到：%v", err)
	}

	_, err = cipher.Decrypt([]byte("shortblock"))
	if err != ErrInvalidBlockSize {
		t.Errorf("对于短块，预期 ErrInvalidBlockSize，但得到：%v", err)
	}
}

// 测试向量测试
func TestRc5Vectors(t *testing.T) {
	// 这些值可以从参考实现或标准中获取
	// 注意：这里的值是模拟的，实际使用时应替换为已知的测试向量
	vectors := []struct {
		key        string
		plaintext  string
		ciphertext string
		rounds     int
		wordSize   int
	}{
		{
			// 这只是一个示例向量，应该用实际的已知值替换
			key:        "000102030405060708090A0B0C0D0E0F",
			plaintext:  "0001020304050607",
			ciphertext: "", // 这里应填入期望的密文
			rounds:     12,
			wordSize:   32,
		},
	}

	// 仅当有实际测试向量时进行测试
	if vectors[0].ciphertext != "" {
		for i, v := range vectors {
			key, _ := hex.DecodeString(v.key)
			plaintext, _ := hex.DecodeString(v.plaintext)
			expectedCiphertext, _ := hex.DecodeString(v.ciphertext)

			cipher, err := NewWithParams(key, v.rounds, v.wordSize)
			if err != nil {
				t.Fatalf("测试向量 %d: 创建RC5实例失败: %v", i, err)
			}

			ciphertext, err := cipher.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("测试向量 %d: 加密失败: %v", i, err)
			}

			if !bytes.Equal(ciphertext, expectedCiphertext) {
				t.Errorf("测试向量 %d: 加密结果不匹配\n期望: %s\n得到: %s",
					i, hex.EncodeToString(expectedCiphertext), hex.EncodeToString(ciphertext))
			}
		}
	}
}

// 测试RC5的BlockSize方法
func TestRc5BlockSize(t *testing.T) {
	key := []byte("0123456789abcdef")
	cipher, err := New(key)
	if err != nil {
		t.Fatalf("创建RC5实例失败: %v", err)
	}

	if cipher.BlockSize() != BlockSize {
		t.Errorf("预期块大小为 %d，但得到：%d", BlockSize, cipher.BlockSize())
	}
}
