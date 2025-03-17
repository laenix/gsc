package sm2

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// 测试生成密钥对
func TestGenerateKey(t *testing.T) {
	sm2Instance := New()
	privateKey, err := sm2Instance.GenerateKey(nil)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	// 检查私钥是否存在
	if privateKey.D == nil {
		t.Fatal("生成的私钥D为空")
	}

	// 检查公钥是否存在
	if privateKey.X == nil || privateKey.Y == nil {
		t.Fatal("生成的公钥坐标为空")
	}

	// 验证公钥是否在曲线上
	if !sm2Instance.curve.IsOnCurve(privateKey.X, privateKey.Y) {
		t.Fatal("生成的公钥不在SM2曲线上")
	}
}

// 测试加密和解密
func TestEncryptDecrypt(t *testing.T) {
	sm2Instance := New()

	// 生成密钥对
	privateKey, err := sm2Instance.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	// 测试不同长度的明文
	plaintexts := [][]byte{
		[]byte("a"),          // 单个字符
		[]byte("abc"),        // 短字符串
		[]byte("这是一段中文测试文本"), // 中文文本
		[]byte("This is a longer text that will be used to test SM2 encryption and decryption"), // 长文本
		bytes.Repeat([]byte{0x01}, 1000), // 重复字节
	}

	for i, plaintext := range plaintexts {
		// 加密
		ciphertext, err := sm2Instance.Encrypt(&privateKey.PublicKey, plaintext, rand.Reader)
		if err != nil {
			t.Fatalf("测试 #%d: 加密失败: %v", i, err)
		}

		// 解密
		decrypted, err := sm2Instance.Decrypt(privateKey, ciphertext)
		if err != nil {
			t.Fatalf("测试 #%d: 解密失败: %v", i, err)
		}

		// 验证解密结果
		if !bytes.Equal(plaintext, decrypted) {
			t.Fatalf("测试 #%d: 解密结果不匹配，期望: %v, 实际: %v", i, plaintext, decrypted)
		}
	}

	// 单独测试空字符串
	t.Run("空字符串", func(t *testing.T) {
		emptyPlaintext := []byte{}
		// 对于空明文，我们期望加密后的密文仍然是有效的
		ciphertext, err := sm2Instance.Encrypt(&privateKey.PublicKey, emptyPlaintext, rand.Reader)
		if err != nil {
			t.Fatalf("空明文加密失败: %v", err)
		}

		decrypted, err := sm2Instance.Decrypt(privateKey, ciphertext)
		if err != nil {
			t.Fatalf("空明文解密失败: %v", err)
		}

		if len(decrypted) != 0 {
			t.Fatalf("空明文解密结果不匹配，期望空字节数组，实际长度: %d", len(decrypted))
		}
	})
}

// 测试签名和验证
func TestSignVerify(t *testing.T) {
	sm2Instance := New()

	// 生成密钥对
	privateKey, err := sm2Instance.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	// 测试消息
	messages := [][]byte{
		[]byte(""),            // 空字符串
		[]byte("Hello, SM2!"), // 简单消息
		[]byte("这是一段需要签名的中文信息"),          // 中文消息
		bytes.Repeat([]byte{0xAA}, 1000), // 重复字节
	}

	for i, message := range messages {
		// 计算消息摘要（在实际应用中，通常会使用SM3哈希算法）
		digest := message // 简化，直接使用消息作为摘要

		// 签名
		signature, err := sm2Instance.Sign(privateKey, digest)
		if err != nil {
			t.Fatalf("测试 #%d: 签名失败: %v", i, err)
		}

		// 验证签名正确性
		valid := sm2Instance.Verify(&privateKey.PublicKey, digest, signature)
		if !valid {
			t.Fatalf("测试 #%d: 签名验证失败，应为正确", i)
		}

		// 修改消息，验证签名应当失败
		if len(digest) > 0 {
			modifiedDigest := make([]byte, len(digest))
			copy(modifiedDigest, digest)
			modifiedDigest[0] ^= 0xFF // 修改第一个字节

			valid = sm2Instance.Verify(&privateKey.PublicKey, modifiedDigest, signature)
			if valid {
				t.Fatalf("测试 #%d: 使用修改后的消息验证签名成功，应当失败", i)
			}
		}
	}
}

// 测试带ID的签名和验证
func TestSignVerifyWithId(t *testing.T) {
	sm2Instance := New()

	// 生成密钥对
	privateKey, err := sm2Instance.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	// 测试消息
	message := []byte("This is a message to be signed with ID")

	// 用户ID
	uid := []byte("1234567812345678")

	// 带ID签名
	signature, err := sm2Instance.SignWithId(privateKey, message, uid)
	if err != nil {
		t.Fatalf("带ID签名失败: %v", err)
	}

	// 验证带ID签名
	valid := sm2Instance.VerifyWithId(&privateKey.PublicKey, message, signature, uid)
	if !valid {
		t.Fatal("带ID签名验证失败，应为正确")
	}

	// 使用不同的ID验证，应当失败
	differentUid := []byte("8765432187654321")
	valid = sm2Instance.VerifyWithId(&privateKey.PublicKey, message, signature, differentUid)
	if valid {
		t.Fatal("使用不同ID验证签名成功，应当失败")
	}

	// 修改消息，验证应当失败
	modifiedMessage := []byte("This is a modified message")
	valid = sm2Instance.VerifyWithId(&privateKey.PublicKey, modifiedMessage, signature, uid)
	if valid {
		t.Fatal("使用修改后的消息验证签名成功，应当失败")
	}
}

// 测试编码和解码私钥
func TestEncodeDecodePrivateKey(t *testing.T) {
	sm2Instance := New()

	// 生成密钥对
	privateKey, err := sm2Instance.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	// 编码私钥
	encodedKey := privateKey.EncodePrivateKey()

	// 解码私钥
	decodedKey, err := sm2Instance.DecodePrivateKey(encodedKey)
	if err != nil {
		t.Fatalf("解码私钥失败: %v", err)
	}

	// 验证解码后的私钥是否和原始私钥相同
	if privateKey.D.Cmp(decodedKey.D) != 0 {
		t.Fatal("解码后的私钥D值与原始值不匹配")
	}

	// 验证从私钥计算出的公钥是否和原始公钥相同
	if privateKey.X.Cmp(decodedKey.X) != 0 || privateKey.Y.Cmp(decodedKey.Y) != 0 {
		t.Fatal("解码后的公钥坐标与原始值不匹配")
	}
}

// 测试编码和解码公钥
func TestEncodeDecodePublicKey(t *testing.T) {
	sm2Instance := New()

	// 生成密钥对
	privateKey, err := sm2Instance.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	// 编码公钥
	publicKey := &privateKey.PublicKey
	encodedKey := publicKey.EncodePublicKey()

	// 解码公钥
	decodedKey, err := sm2Instance.DecodePublicKey(encodedKey)
	if err != nil {
		t.Fatalf("解码公钥失败: %v", err)
	}

	// 验证解码后的公钥是否和原始公钥相同
	if publicKey.X.Cmp(decodedKey.X) != 0 || publicKey.Y.Cmp(decodedKey.Y) != 0 {
		t.Fatal("解码后的公钥坐标与原始值不匹配")
	}
}

// 测试错误处理
func TestErrorCases(t *testing.T) {
	sm2Instance := New()

	// 生成密钥对
	privateKey, err := sm2Instance.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
	}

	// 测试无效的私钥解密
	invalidPrivateKey := &PrivateKey{D: nil, PublicKey: privateKey.PublicKey}
	_, err = sm2Instance.Decrypt(invalidPrivateKey, []byte{0x04, 0x01})
	if err == nil {
		t.Fatal("使用无效私钥解密应当失败")
	}

	// 测试无效的密文解密
	shortCiphertext := []byte{0x04, 0x01, 0x02}
	_, err = sm2Instance.Decrypt(privateKey, shortCiphertext)
	if err == nil {
		t.Fatal("解密过短的密文应当失败")
	}

	// 测试无效的私钥签名
	_, err = sm2Instance.Sign(invalidPrivateKey, []byte("test"))
	if err == nil {
		t.Fatal("使用无效私钥签名应当失败")
	}

	// 测试无效的公钥验证
	invalidPublicKey := &PublicKey{X: nil, Y: nil}
	if sm2Instance.Verify(invalidPublicKey, []byte("test"), []byte("signature")) {
		t.Fatal("使用无效公钥验证签名应当失败")
	}
}

// 基准测试 - 密钥生成
func BenchmarkGenerateKey(b *testing.B) {
	sm2Instance := New()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sm2Instance.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("生成密钥对失败: %v", err)
		}
	}
}

// 基准测试 - 加密
func BenchmarkEncrypt(b *testing.B) {
	sm2Instance := New()
	privateKey, _ := sm2Instance.GenerateKey(rand.Reader)
	plaintext := []byte("This is a test message for encryption benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm2Instance.Encrypt(&privateKey.PublicKey, plaintext, rand.Reader)
		if err != nil {
			b.Fatalf("加密失败: %v", err)
		}
	}
}

// 基准测试 - 解密
func BenchmarkDecrypt(b *testing.B) {
	sm2Instance := New()
	privateKey, _ := sm2Instance.GenerateKey(rand.Reader)
	plaintext := []byte("This is a test message for decryption benchmark")
	ciphertext, _ := sm2Instance.Encrypt(&privateKey.PublicKey, plaintext, rand.Reader)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm2Instance.Decrypt(privateKey, ciphertext)
		if err != nil {
			b.Fatalf("解密失败: %v", err)
		}
	}
}

// 基准测试 - 签名
func BenchmarkSign(b *testing.B) {
	sm2Instance := New()
	privateKey, _ := sm2Instance.GenerateKey(rand.Reader)
	message := []byte("This is a test message for signing benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm2Instance.Sign(privateKey, message)
		if err != nil {
			b.Fatalf("签名失败: %v", err)
		}
	}
}

// 基准测试 - 验证
func BenchmarkVerify(b *testing.B) {
	sm2Instance := New()
	privateKey, _ := sm2Instance.GenerateKey(rand.Reader)
	message := []byte("This is a test message for verification benchmark")
	signature, _ := sm2Instance.Sign(privateKey, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sm2Instance.Verify(&privateKey.PublicKey, message, signature)
	}
}
