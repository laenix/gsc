# github.com/laenix/gsc (Go Simple Crypto)

这是一个用Go语言实现的分组密码教学项目，旨在帮助学习者理解常见的分组密码算法（如AES、DES）及其工作模式。本项目的代码经过精心设计，注重可读性和教学价值，适合密码学初学者学习和参考。

## 项目特点

- 清晰的代码结构和详细的注释
- 完整实现了AES和DES算法
- 支持多种分组密码工作模式（ECB、CBC、CFB、OFB、CTR、GCM）
- 包含PKCS#7和零填充等常用填充方式
- 提供丰富的示例和测试用例

## 项目结构

```
github.com/laenix/gsc/
├── aes/            - AES算法实现
│   └── internal/   - AES算法内部常量和辅助函数
├── des/            - DES算法实现
│   └── internal/   - DES算法内部常量和辅助函数
├── modes/          - 分组密码工作模式
│   ├── modes.go   - 通用接口定义
│   ├── ecb.go     - ECB模式实现
│   ├── cbc.go     - CBC模式实现
│   ├── cfb.go     - CFB模式实现
│   ├── ofb.go     - OFB模式实现
│   ├── ctr.go     - CTR模式实现
│   ├── gcm.go     - GCM模式实现
│   └── internal/  - 内部辅助函数
├── padding/        - 填充方式
│   ├── pkcs7.go   - PKCS#7填充
│   └── zero.go    - 零填充
└── test/          - 测试用例
    ├── aes/       - AES相关测试
    ├── des/       - DES相关测试
    └── modes/     - 加密模式测试
```

## 算法实现

### AES (Advanced Encryption Standard)

- 支持128/192/256位密钥长度
- 实现了完整的加密和解密过程
- 包含密钥扩展、SubBytes、ShiftRows、MixColumns等操作
- 使用查表优化的S-box实现

### DES (Data Encryption Standard)

- 支持64位密钥（实际使用56位）
- 实现了完整的Feistel网络结构
- 包含初始置换（IP）、最终置换（IP^-1）
- 实现了16轮Feistel函数，包括：
  - 扩展置换（E）
  - S-box替换
  - P-box置换
  - 密钥调度算法

### 分组密码工作模式

1. ECB (Electronic Codebook)
   - 最简单的工作模式
   - 相同的明文块产生相同的密文块
   - 不推荐用于实际应用
   - 适合教学理解基本概念

2. CBC (Cipher Block Chaining)
   - 使用前一个密文块来加密当前明文块
   - 需要初始化向量（IV）
   - 提供更好的安全性
   - 不支持并行处理

3. CFB (Cipher Feedback)
   - 将分组密码转换为流密码
   - 需要初始化向量（IV）
   - 支持实时加密
   - 错误传播限制在一个分组内

4. OFB (Output Feedback)
   - 将分组密码转换为流密码
   - 需要初始化向量（IV）
   - 预先生成密钥流
   - 不会产生错误传播

5. CTR (Counter)
   - 将分组密码转换为流密码
   - 使用计数器生成密钥流
   - 支持并行处理
   - 无需填充

6. GCM (Galois/Counter Mode)
   - 基于CTR模式
   - 提供认证功能（AEAD）
   - 支持额外认证数据（AAD）
   - 高效且安全

## 使用示例

### AES加密示例

```go
package main

import (
    "fmt"
    "github.com/laenix/gsc/aes"
    "github.com/laenix/gsc/modes"
    "github.com/laenix/gsc/padding"
)

func main() {
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
```

### DES加密示例

```go
package main

import (
    "fmt"
    "github.com/laenix/gsc/des"
    "github.com/laenix/gsc/padding"
)

func main() {
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
```

## 安全提示

1. 本项目仅用于教学目的，不建议在生产环境中使用
2. 在实际应用中，应使用标准库的加密实现
3. ECB模式不安全，不应在实际应用中使用
4. 使用CBC/CFB/OFB模式时，必须使用安全的随机IV
5. 建议使用GCM等AEAD模式来提供数据认证
6. DES算法已不再安全，仅用于学习目的

## 贡献

欢迎提交Issue和Pull Request来改进这个教学项目。如果您发现任何问题或有改进建议，请随时提出。

## 许可证

MIT License 