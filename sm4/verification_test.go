package sm4

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/laenix/gsc/modes"
	"github.com/laenix/gsc/padding"
)

func TestSM4ECBVerification(t *testing.T) {
	// 使用给定的密钥
	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")

	// 明文字符串
	plaintext := []byte("这是SM4加密算法的测试文本，长度超过一个块。")

	// 创建SM4实例
	cipher, _ := New(key)

	// 检查轮密钥生成
	t.Run("RoundKeysCheck", func(t *testing.T) {
		// 检查轮密钥是否生成（不比较具体值，只检查是否有32个轮密钥）
		if len(cipher.roundKeys) != 32 {
			t.Errorf("轮密钥生成错误: 期望32个轮密钥，但是得到%d个", len(cipher.roundKeys))
		}

		// 输出轮密钥
		for i, k := range cipher.roundKeys {
			t.Logf("轮密钥 %d: %08x", i, k)
		}
	})

	// ECB模式加密测试
	t.Run("ECBEncryptionCheck", func(t *testing.T) {
		// 使用ECB模式
		ecb := modes.NewECB(cipher)

		// PKCS7填充
		paddedPlaintext, _ := padding.PKCS7Padding(plaintext, cipher.BlockSize())

		// 加密
		ciphertext, err := ecb.Encrypt(paddedPlaintext)
		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}

		// 期望的结果（去掉空格）
		expectedHex := strings.ReplaceAll("6E 9A 07 5B 7C 68 AF 69 CE 70 EE FB D9 CA CA 70 C6 65 05 0E 5D 53 4B 2B 59 8E 9A 89 01 92 A4 9E BD 74 BD 59 FF 6C 58 40 58 0F E8 AB 61 C9 19 1E A4 32 47 08 30 94 B9 96 C9 0B 88 4A 71 D4 2D 08", " ", "")
		expected, _ := hex.DecodeString(expectedHex)

		// 比较结果
		if !bytes.Equal(ciphertext, expected) {
			t.Errorf("\n期望的加密结果: %x\n实际的加密结果: %x", expected, ciphertext)

			// 如果不匹配，逐块比较
			blockSize := cipher.BlockSize()
			for i := 0; i < len(ciphertext)/blockSize; i++ {
				start := i * blockSize
				end := start + blockSize
				if end > len(ciphertext) {
					end = len(ciphertext)
				}

				expectedBlock := expected[start:end]
				actualBlock := ciphertext[start:end]

				if !bytes.Equal(expectedBlock, actualBlock) {
					t.Errorf("第%d块不匹配:\n期望: %x\n实际: %x", i+1, expectedBlock, actualBlock)
				}
			}
		} else {
			t.Logf("加密结果匹配！")
		}
	})

	// 检查SM4的基本功能：单块加密和解密
	t.Run("SingleBlockTest", func(t *testing.T) {
		singleBlock := make([]byte, BlockSize)
		copy(singleBlock, plaintext)

		// 加密单块
		encrypted, err := cipher.Encrypt(singleBlock)
		if err != nil {
			t.Fatalf("单块加密失败: %v", err)
		}

		// 解密单块
		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			t.Fatalf("单块解密失败: %v", err)
		}

		// 验证加解密结果
		if !bytes.Equal(singleBlock, decrypted) {
			t.Errorf("单块加解密结果不匹配:\n原文: %x\n解密: %x", singleBlock, decrypted)
		}
	})

	// 输出分析结果
	t.Run("DiagnosticOutput", func(t *testing.T) {
		t.Logf("密钥: %x", key)
		t.Logf("明文: %s", plaintext)
		t.Logf("明文(Hex): %x", plaintext)
		t.Log("如果测试失败，请检查以下可能的问题:")
		t.Log("1. T变换中的线性变换L实现是否正确")
		t.Log("2. S盒的值是否正确")
		t.Log("3. 轮密钥扩展算法是否正确")
		t.Log("4. 密钥、明文的字节顺序处理是否正确")
	})
}
