package examples

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/laenix/gsc/aes"
	"github.com/laenix/gsc/blowfish"
	"github.com/laenix/gsc/des"
	"github.com/laenix/gsc/modes"
	"github.com/laenix/gsc/padding"
	"github.com/laenix/gsc/twofish"
)

type Options struct {
	// 迭代次数
	Iterations int
	// 加盐位置
	SaltPosition string
	// 盐值
	SaltValue []byte
	// key
	Key []byte
	// key2 3des
	Key2 string
	// key3 3des
	Key3 string
	// iv
	Iv []byte
	// mode aes/ecb/cbc/ctr/
	Mode string
	// padding pkcs7/pkcs5/none
	Padding string
	// random chacha20/chacha20poly1305/xsalsa20/xsalsa20poly1305
	Random string
	// keylen aes 128/192/256
	Keylen string
	// usera
	UserA string
	// userb
	UserB string
	// Block Size
	BlockSize int
}

func Padding(plaintext []byte, opt *Options) ([]byte, error) {
	paddedPlaintext := plaintext
	var err error
	// 填充
	switch opt.Padding {
	case "PKCS#7":
		paddedPlaintext, err = padding.PKCS7Padding(plaintext, opt.BlockSize)
	case "M1":
		paddedPlaintext, err = padding.M1Padding(plaintext, opt.BlockSize)
	case "M1(+0)":
		paddedPlaintext, err = padding.M1PlusZeroPadding(plaintext, opt.BlockSize)
	case "M2":
		paddedPlaintext, err = padding.M2Padding(plaintext, opt.BlockSize)
	case "ISO7816":
		paddedPlaintext, err = padding.ISO7816Padding(plaintext, opt.BlockSize)
	case "ANSIX923":
		paddedPlaintext, err = padding.ANSIX923Padding(plaintext, opt.BlockSize)
	case "Zero":
		paddedPlaintext, err = padding.ZeroPadding(plaintext, opt.BlockSize)
	case "PKCS#5":
		paddedPlaintext, err = padding.PKCS5Padding(plaintext)
	case "ISO10126":
		paddedPlaintext, err = padding.ISO10126Padding(plaintext, opt.BlockSize)
	case "TBC":
		paddedPlaintext, err = padding.TBCPadding(plaintext, opt.BlockSize)
	case "None":
		paddedPlaintext = plaintext
	}

	if err != nil {
		return nil, err
	}
	return paddedPlaintext, nil
}

func AES_Encrypt(plaintext []byte, opt *Options) ([]byte, error) {
	paddedPlaintext, err := Padding(plaintext, opt)
	if err != nil {
		return nil, err
	}
	// 创建AES实例
	cipher, err := aes.New(opt.Key)
	if err != nil {
		return nil, err
	}
	// 判断大小
	if len(paddedPlaintext)%opt.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext length must be a multiple of the block size")
	}
	// 创建分组模式实例
	var ciphertext []byte
	switch opt.Mode {
	case "ECB":
		ecb := modes.NewECB(cipher)
		ciphertext, err = ecb.Encrypt(paddedPlaintext)
		if err != nil {
			return nil, err
		}
	case "CBC":
		cbc, err := modes.NewCBC(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		ciphertext, err = cbc.Encrypt(paddedPlaintext)
		if err != nil {
			return nil, err
		}
	case "CFB":
		cfb, err := modes.NewCFB(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		ciphertext, err = cfb.Encrypt(plaintext)
		if err != nil {
			return nil, err
		}
	case "OFB":
		ofb, err := modes.NewOFB(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		ciphertext, err = ofb.Encrypt(paddedPlaintext)
		if err != nil {
			return nil, err
		}
	case "CTR":
		ctr, err := modes.NewCTR(cipher, opt.Iv)
		if err != nil {
			return nil, err

		}
		ciphertext, err = ctr.Encrypt(paddedPlaintext)
		if err != nil {
			return nil, err
		}
	case "GCM":
		gcm, err := modes.NewGCM(cipher)
		if err != nil {
			return nil, err
		}
		// 随机生成的12字节Nonce（在实际应用中应该是随机的）
		nonce := []byte("123456789012")

		// 附加验证数据（可选）
		aad := []byte("附加验证数据")
		ciphertext, err = gcm.Seal(nonce, plaintext, aad)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported mode: %s", opt.Mode)

	}
	// 返回密文
	return ciphertext, nil
}

func AES_Decrypt(ciphertext []byte, opt *Options) ([]byte, error) {
	// 创建AES实例
	cipher, err := aes.New(opt.Key)
	if err != nil {
		return nil, err
	}

	// 创建分组模式实例
	var plaintext []byte
	switch opt.Mode {
	case "ECB":
		ecb := modes.NewECB(cipher)
		plaintext, err = ecb.Decrypt(ciphertext)
	case "CBC":
		cbc, err := modes.NewCBC(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		plaintext, err = cbc.Decrypt(ciphertext)
	case "CFB":
		cfb, err := modes.NewCFB(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		plaintext, err = cfb.Decrypt(ciphertext)
	case "OFB":
		ofb, err := modes.NewOFB(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		plaintext, err = ofb.Decrypt(ciphertext)
	case "CTR":
		ctr, err := modes.NewCTR(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		plaintext, err = ctr.Decrypt(ciphertext)
	case "GCM":
		gcm, err := modes.NewGCM(cipher)
		if err != nil {
			return nil, err
		}
		// 从密文中提取nonce（前12字节）和认证标签（后16字节）
		nonce := ciphertext[:12]
		// 附加验证数据（需要与加密时相同）
		aad := []byte("附加验证数据")
		plaintext, err = gcm.Open(nonce, ciphertext[12:], aad)
	default:
		return nil, fmt.Errorf("unsupported mode: %s", opt.Mode)
	}

	if err != nil {
		return nil, err
	}

	// 去除填充
	if opt.Padding != "None" && opt.Mode != "CFB" && opt.Mode != "CTR" && opt.Mode != "GCM" {
		switch opt.Padding {
		case "PKCS#7":
			plaintext, err = padding.PKCS7UnPadding(plaintext)
		case "M1":
			plaintext, err = padding.M1UnPadding(plaintext)
		case "M1(+0)":
			plaintext, err = padding.M1UnPadding(plaintext)
		case "M2":
			plaintext, err = padding.M2UnPadding(plaintext)
		case "ISO7816":
			plaintext, err = padding.ISO7816UnPadding(plaintext)
		case "ANSIX923":
			plaintext, err = padding.ANSIX923UnPadding(plaintext)
		case "Zero":
			plaintext, err = padding.ZeroUnPadding(plaintext)
		case "PKCS#5":
			plaintext, err = padding.PKCS5UnPadding(plaintext)
		// case "ISO10126":
		// 	plaintext, err = padding.ISO10126UnPadding(plaintext)
		case "TBC":
			plaintext, err = padding.TBCUnPadding(plaintext)
		}
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}

func DES_Encrypt(plaintext []byte, opt *Options) ([]byte, error) {
	paddedPlaintext, err := Padding(plaintext, opt)
	if err != nil {
		return nil, err
	}
	// 创建AES实例
	cipher, err := des.New(opt.Key)
	if err != nil {
		return nil, err
	}
	// 判断大小
	if len(paddedPlaintext)%opt.BlockSize != 0 {
		return nil, fmt.Errorf("plaintext length must be a multiple of the block size")
	}
	// 创建分组模式实例
	var ciphertext []byte
	switch opt.Mode {
	case "ECB":
		ecb := modes.NewECB(cipher)
		ciphertext, err = ecb.Encrypt(paddedPlaintext)
		if err != nil {
			return nil, err
		}
	case "CBC":
		cbc, err := modes.NewCBC(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		ciphertext, err = cbc.Encrypt(paddedPlaintext)
		if err != nil {
			return nil, err
		}
	case "CFB":
		cfb, err := modes.NewCFB(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		ciphertext, err = cfb.Encrypt(plaintext)
		if err != nil {
			return nil, err
		}
	case "OFB":
		ofb, err := modes.NewOFB(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		ciphertext, err = ofb.Encrypt(paddedPlaintext)
		if err != nil {
			return nil, err
		}
	case "CTR":
		ctr, err := modes.NewCTR(cipher, opt.Iv)
		if err != nil {
			return nil, err

		}
		ciphertext, err = ctr.Encrypt(paddedPlaintext)
		if err != nil {
			return nil, err
		}
	case "GCM":
		gcm, err := modes.NewGCM(cipher)
		if err != nil {
			return nil, err
		}
		// 随机生成的12字节Nonce（在实际应用中应该是随机的）
		nonce := []byte("123456789012")

		// 附加验证数据（可选）
		aad := []byte("附加验证数据")
		ciphertext, err = gcm.Seal(nonce, plaintext, aad)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported mode: %s", opt.Mode)

	}
	// 返回密文
	return ciphertext, nil
}

func DES_Decrypt(ciphertext []byte, opt *Options) ([]byte, error) {
	// 创建DES实例
	cipher, err := des.New(opt.Key)
	if err != nil {
		return nil, err
	}

	// 创建分组模式实例
	var plaintext []byte
	switch opt.Mode {
	case "ECB":
		ecb := modes.NewECB(cipher)
		plaintext, err = ecb.Decrypt(ciphertext)
	case "CBC":
		cbc, err := modes.NewCBC(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		plaintext, err = cbc.Decrypt(ciphertext)
	case "CFB":
		cfb, err := modes.NewCFB(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		plaintext, err = cfb.Decrypt(ciphertext)
	case "OFB":
		ofb, err := modes.NewOFB(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		plaintext, err = ofb.Decrypt(ciphertext)
	case "CTR":
		ctr, err := modes.NewCTR(cipher, opt.Iv)
		if err != nil {
			return nil, err
		}
		plaintext, err = ctr.Decrypt(ciphertext)
	case "GCM":
		gcm, err := modes.NewGCM(cipher)
		if err != nil {
			return nil, err
		}
		// 从密文中提取nonce（前12字节）和认证标签（后16字节）
		nonce := ciphertext[:12]
		// 附加验证数据（需要与加密时相同）
		aad := []byte("附加验证数据")
		plaintext, err = gcm.Open(nonce, ciphertext[12:], aad)
	default:
		return nil, fmt.Errorf("unsupported mode: %s", opt.Mode)
	}

	if err != nil {
		return nil, err
	}

	// 去除填充
	if opt.Padding != "None" && opt.Mode != "CFB" && opt.Mode != "CTR" && opt.Mode != "GCM" {
		switch opt.Padding {
		case "PKCS#7":
			plaintext, err = padding.PKCS7UnPadding(plaintext)
		case "M1":
			plaintext, err = padding.M1UnPadding(plaintext)
		case "M1(+0)":
			plaintext, err = padding.M1UnPadding(plaintext)
		case "M2":
			plaintext, err = padding.M2UnPadding(plaintext)
		case "ISO7816":
			plaintext, err = padding.ISO7816UnPadding(plaintext)
		case "ANSIX923":
			plaintext, err = padding.ANSIX923UnPadding(plaintext)
		case "Zero":
			plaintext, err = padding.ZeroUnPadding(plaintext)
		case "PKCS#5":
			plaintext, err = padding.PKCS5UnPadding(plaintext)
		// case "ISO10126":
		// 	plaintext, err = padding.ISO10126UnPadding(plaintext)
		case "TBC":
			plaintext, err = padding.TBCUnPadding(plaintext)
		}
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}

func AES_test() {
	// 测试数据
	plaintext := []byte("Hello, World! This is a test message for AES encryption.")

	// 定义要测试的模式和填充方式
	modes := []string{"ECB", "CBC", "CFB", "OFB", "CTR", "GCM"}
	paddings := []string{"PKCS#7", "PKCS#5", "ISO7816", "Zero"}

	// AES-256密钥（32字节）
	key := []byte("12345678901234567890123456789012")
	// 初始化向量（16字节）
	iv := []byte("1234567890123456")

	fmt.Println("=== AES 加密测试 ===")
	fmt.Printf("原文: %s\n", string(plaintext))

	for _, mode := range modes {
		for _, paddingType := range paddings {
			// 对于CFB、CTR和GCM模式，跳过填充测试（因为它们不需要填充）
			if (mode == "CFB" || mode == "CTR" || mode == "GCM") && paddingType != "PKCS#7" {
				continue
			}

			fmt.Printf("\n测试模式: %s, 填充方式: %s\n", mode, paddingType)

			opt := &Options{
				Key:       key,
				Iv:        iv,
				Mode:      mode,
				Padding:   paddingType,
				BlockSize: 16,
			}

			// 加密
			ciphertext, err := AES_Encrypt(plaintext, opt)
			if err != nil {
				fmt.Printf("加密错误: %v\n", err)
				continue
			}
			fmt.Printf("密文(hex): %x\n", ciphertext)

			// 解密
			decrypted, err := AES_Decrypt(ciphertext, opt)
			if err != nil {
				fmt.Printf("解密错误: %v\n", err)
				continue
			}
			fmt.Printf("解密结果: %s\n", string(decrypted))

			// 验证
			if string(decrypted) == string(plaintext) {
				fmt.Println("✓ 验证成功：解密结果与原文匹配")
			} else {
				fmt.Println("✗ 验证失败：解密结果与原文不匹配")
			}
		}
	}
}

func DES_test() {
	// 测试数据
	plaintext := []byte("Hello, World! This is a test message for DES.")
	expectedCiphertext, _ := hex.DecodeString("20ae8742d6c06b9c74671cdf3925c5b55eb620908624690c426834c48254a186c84ea64eaf3d5e4c841607297ab93f7e")

	// DES密钥（8字节，64位）
	key := []byte{
		0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
	}

	fmt.Println("\n=== DES 加密测试（ECB模式）===")
	fmt.Printf("原文: %s\n", string(plaintext))
	fmt.Printf("原文(hex): %X\n", plaintext)
	fmt.Printf("密钥(hex): %X\n", key)
	fmt.Printf("期望密文(hex): %X\n", expectedCiphertext)

	opt := &Options{
		Key:       key,
		Mode:      "ECB",
		Padding:   "PKCS#7",
		BlockSize: 8, // DES的块大小是8字节
	}

	// 加密
	ciphertext, err := DES_Encrypt(plaintext, opt)
	if err != nil {
		fmt.Printf("加密错误: %v\n", err)
		return
	}
	fmt.Printf("实际密文(hex): %X\n", ciphertext)

	// 解密
	decrypted, err := DES_Decrypt(ciphertext, opt)
	if err != nil {
		fmt.Printf("解密错误: %v\n", err)
		return
	}
	fmt.Printf("解密结果: %s\n", string(decrypted))

	// 验证解密结果
	if string(decrypted) == string(plaintext) {
		fmt.Println("✓ 解密验证成功：解密结果与原文匹配")
	} else {
		fmt.Println("✗ 解密验证失败：解密结果与原文不匹配")
	}

	// 验证与期望密文的匹配情况
	if bytes.Equal(ciphertext, expectedCiphertext) {
		fmt.Println("✓ 密文验证成功：生成的密文与期望密文匹配")
	} else {
		fmt.Println("✗ 密文验证失败：生成的密文与期望密文不匹配")
		fmt.Println("\n差异分析：")
		if len(ciphertext) != len(expectedCiphertext) {
			fmt.Printf("长度不匹配：实际长度=%d, 期望长度=%d\n", len(ciphertext), len(expectedCiphertext))
		} else {
			fmt.Println("按块比对（每8字节一块）：")
			for i := 0; i < len(ciphertext); i += 8 {
				end := i + 8
				if end > len(ciphertext) {
					end = len(ciphertext)
				}
				fmt.Printf("块 %d: 实际=%X\n", i/8+1, ciphertext[i:end])
				fmt.Printf("     期望=%X\n", expectedCiphertext[i:end])
				if !bytes.Equal(ciphertext[i:end], expectedCiphertext[i:end]) {
					fmt.Println("     ↑ 此块不匹配")
				}
			}
		}
	}
}

func Blowfish_Encrypt(plaintext []byte, opt *Options) ([]byte, error) {
	// 设置块大小
	opt.BlockSize = blowfish.BlockSize

	// 填充
	paddedPlaintext, err := Padding(plaintext, opt)
	if err != nil {
		return nil, err
	}

	// 创建Blowfish实例
	bf, err := blowfish.New(opt.Key)
	if err != nil {
		return nil, err
	}

	blockSize := bf.BlockSize()
	ciphertext := make([]byte, len(paddedPlaintext))

	// 根据模式进行加密
	switch opt.Mode {
	case "ECB":
		// ECB模式
		for i := 0; i < len(paddedPlaintext); i += blockSize {
			block, err := bf.Encrypt(paddedPlaintext[i : i+blockSize])
			if err != nil {
				return nil, err
			}
			copy(ciphertext[i:i+blockSize], block)
		}
	case "CBC":
		// CBC模式
		iv := opt.Iv
		if iv == nil || len(iv) != blockSize {
			return nil, fmt.Errorf("CBC模式需要%d字节的初始化向量", blockSize)
		}

		previousBlock := iv
		for i := 0; i < len(paddedPlaintext); i += blockSize {
			// 将明文块与前一个密文块（或IV）进行XOR
			block := make([]byte, blockSize)
			for j := 0; j < blockSize; j++ {
				block[j] = paddedPlaintext[i+j] ^ previousBlock[j]
			}

			// 加密
			encryptedBlock, err := bf.Encrypt(block)
			if err != nil {
				return nil, err
			}

			// 保存结果
			copy(ciphertext[i:i+blockSize], encryptedBlock)
			previousBlock = encryptedBlock
		}
	case "CTR":
		// CTR模式
		counter := opt.Iv
		if counter == nil || len(counter) != blockSize {
			return nil, fmt.Errorf("CTR模式需要%d字节的计数器", blockSize)
		}

		counterBlock := make([]byte, blockSize)
		for i := 0; i < len(paddedPlaintext); i += blockSize {
			// 复制计数器
			copy(counterBlock, counter)

			// 加密计数器
			encryptedCounter, err := bf.Encrypt(counterBlock)
			if err != nil {
				return nil, err
			}

			// 与明文进行XOR
			blockLength := blockSize
			if i+blockSize > len(paddedPlaintext) {
				blockLength = len(paddedPlaintext) - i
			}
			for j := 0; j < blockLength; j++ {
				ciphertext[i+j] = paddedPlaintext[i+j] ^ encryptedCounter[j]
			}

			// 增加计数器
			for j := blockSize - 1; j >= 0; j-- {
				counter[j]++
				if counter[j] != 0 {
					break
				}
			}
		}
	default:
		return nil, fmt.Errorf("不支持的加密模式: %s", opt.Mode)
	}

	return ciphertext, nil
}

func Blowfish_Decrypt(ciphertext []byte, opt *Options) ([]byte, error) {
	// 创建Blowfish实例
	bf, err := blowfish.New(opt.Key)
	if err != nil {
		return nil, err
	}

	blockSize := bf.BlockSize()
	plaintext := make([]byte, len(ciphertext))

	// 根据模式进行解密
	switch opt.Mode {
	case "ECB":
		// ECB模式
		for i := 0; i < len(ciphertext); i += blockSize {
			block, err := bf.Decrypt(ciphertext[i : i+blockSize])
			if err != nil {
				return nil, err
			}
			copy(plaintext[i:i+blockSize], block)
		}
	case "CBC":
		// CBC模式
		iv := opt.Iv
		if iv == nil || len(iv) != blockSize {
			return nil, fmt.Errorf("CBC模式需要%d字节的初始化向量", blockSize)
		}

		previousBlock := iv
		for i := 0; i < len(ciphertext); i += blockSize {
			// 解密
			decryptedBlock, err := bf.Decrypt(ciphertext[i : i+blockSize])
			if err != nil {
				return nil, err
			}

			// 与前一个密文块（或IV）进行XOR
			for j := 0; j < blockSize; j++ {
				plaintext[i+j] = decryptedBlock[j] ^ previousBlock[j]
			}

			// 更新前一个密文块
			previousBlock = ciphertext[i : i+blockSize]
		}
	case "CTR":
		// CTR模式
		counter := opt.Iv
		if counter == nil || len(counter) != blockSize {
			return nil, fmt.Errorf("CTR模式需要%d字节的计数器", blockSize)
		}

		counterBlock := make([]byte, blockSize)
		for i := 0; i < len(ciphertext); i += blockSize {
			// 复制计数器
			copy(counterBlock, counter)

			// 加密计数器
			encryptedCounter, err := bf.Encrypt(counterBlock)
			if err != nil {
				return nil, err
			}

			// 与密文进行XOR
			blockLength := blockSize
			if i+blockSize > len(ciphertext) {
				blockLength = len(ciphertext) - i
			}
			for j := 0; j < blockLength; j++ {
				plaintext[i+j] = ciphertext[i+j] ^ encryptedCounter[j]
			}

			// 增加计数器
			for j := blockSize - 1; j >= 0; j-- {
				counter[j]++
				if counter[j] != 0 {
					break
				}
			}
		}
	default:
		return nil, fmt.Errorf("不支持的解密模式: %s", opt.Mode)
	}

	// 移除填充
	switch opt.Padding {
	case "PKCS#7":
		plaintext, err = padding.PKCS7UnPadding(plaintext)
		if err != nil {
			return nil, err
		}
	case "PKCS#5":
		plaintext, err = padding.PKCS5UnPadding(plaintext)
		if err != nil {
			return nil, err
		}
	case "None":
		// 不需要移除填充
	default:
		return nil, fmt.Errorf("不支持的填充方式: %s", opt.Padding)
	}

	return plaintext, nil
}

func Twofish_Encrypt(plaintext []byte, opt *Options) ([]byte, error) {
	// 设置块大小
	opt.BlockSize = twofish.BlockSize

	// 填充
	paddedPlaintext, err := Padding(plaintext, opt)
	if err != nil {
		return nil, err
	}

	// 创建Twofish实例
	tf, err := twofish.New(opt.Key)
	if err != nil {
		return nil, err
	}

	blockSize := tf.BlockSize()
	ciphertext := make([]byte, len(paddedPlaintext))

	// 根据模式进行加密
	switch opt.Mode {
	case "ECB":
		// ECB模式
		for i := 0; i < len(paddedPlaintext); i += blockSize {
			block, err := tf.Encrypt(paddedPlaintext[i : i+blockSize])
			if err != nil {
				return nil, err
			}
			copy(ciphertext[i:i+blockSize], block)
		}
	case "CBC":
		// CBC模式
		iv := opt.Iv
		if iv == nil || len(iv) != blockSize {
			return nil, fmt.Errorf("CBC模式需要%d字节的初始化向量", blockSize)
		}

		previousBlock := iv
		for i := 0; i < len(paddedPlaintext); i += blockSize {
			// 将明文块与前一个密文块（或IV）进行XOR
			block := make([]byte, blockSize)
			for j := 0; j < blockSize; j++ {
				block[j] = paddedPlaintext[i+j] ^ previousBlock[j]
			}

			// 加密
			encryptedBlock, err := tf.Encrypt(block)
			if err != nil {
				return nil, err
			}

			// 保存结果
			copy(ciphertext[i:i+blockSize], encryptedBlock)
			previousBlock = encryptedBlock
		}
	case "CTR":
		// CTR模式
		counter := opt.Iv
		if counter == nil || len(counter) != blockSize {
			return nil, fmt.Errorf("CTR模式需要%d字节的计数器", blockSize)
		}

		counterBlock := make([]byte, blockSize)
		for i := 0; i < len(paddedPlaintext); i += blockSize {
			// 复制计数器
			copy(counterBlock, counter)

			// 加密计数器
			encryptedCounter, err := tf.Encrypt(counterBlock)
			if err != nil {
				return nil, err
			}

			// 与明文进行XOR
			blockLength := blockSize
			if i+blockSize > len(paddedPlaintext) {
				blockLength = len(paddedPlaintext) - i
			}
			for j := 0; j < blockLength; j++ {
				ciphertext[i+j] = paddedPlaintext[i+j] ^ encryptedCounter[j]
			}

			// 增加计数器
			for j := blockSize - 1; j >= 0; j-- {
				counter[j]++
				if counter[j] != 0 {
					break
				}
			}
		}
	default:
		return nil, fmt.Errorf("不支持的加密模式: %s", opt.Mode)
	}

	return ciphertext, nil
}

func Twofish_Decrypt(ciphertext []byte, opt *Options) ([]byte, error) {
	// 创建Twofish实例
	tf, err := twofish.New(opt.Key)
	if err != nil {
		return nil, err
	}

	blockSize := tf.BlockSize()
	plaintext := make([]byte, len(ciphertext))

	// 根据模式进行解密
	switch opt.Mode {
	case "ECB":
		// ECB模式
		for i := 0; i < len(ciphertext); i += blockSize {
			block, err := tf.Decrypt(ciphertext[i : i+blockSize])
			if err != nil {
				return nil, err
			}
			copy(plaintext[i:i+blockSize], block)
		}
	case "CBC":
		// CBC模式
		iv := opt.Iv
		if iv == nil || len(iv) != blockSize {
			return nil, fmt.Errorf("CBC模式需要%d字节的初始化向量", blockSize)
		}

		previousBlock := iv
		for i := 0; i < len(ciphertext); i += blockSize {
			// 解密
			decryptedBlock, err := tf.Decrypt(ciphertext[i : i+blockSize])
			if err != nil {
				return nil, err
			}

			// 与前一个密文块（或IV）进行XOR
			for j := 0; j < blockSize; j++ {
				plaintext[i+j] = decryptedBlock[j] ^ previousBlock[j]
			}

			// 更新前一个密文块
			previousBlock = ciphertext[i : i+blockSize]
		}
	case "CTR":
		// CTR模式
		counter := opt.Iv
		if counter == nil || len(counter) != blockSize {
			return nil, fmt.Errorf("CTR模式需要%d字节的计数器", blockSize)
		}

		counterBlock := make([]byte, blockSize)
		for i := 0; i < len(ciphertext); i += blockSize {
			// 复制计数器
			copy(counterBlock, counter)

			// 加密计数器
			encryptedCounter, err := tf.Encrypt(counterBlock)
			if err != nil {
				return nil, err
			}

			// 与密文进行XOR
			blockLength := blockSize
			if i+blockSize > len(ciphertext) {
				blockLength = len(ciphertext) - i
			}
			for j := 0; j < blockLength; j++ {
				plaintext[i+j] = ciphertext[i+j] ^ encryptedCounter[j]
			}

			// 增加计数器
			for j := blockSize - 1; j >= 0; j-- {
				counter[j]++
				if counter[j] != 0 {
					break
				}
			}
		}
	default:
		return nil, fmt.Errorf("不支持的解密模式: %s", opt.Mode)
	}

	// 移除填充
	switch opt.Padding {
	case "PKCS#7":
		plaintext, err = padding.PKCS7UnPadding(plaintext)
		if err != nil {
			return nil, err
		}
	case "PKCS#5":
		plaintext, err = padding.PKCS5UnPadding(plaintext)
		if err != nil {
			return nil, err
		}
	case "None":
		// 不需要移除填充
	default:
		return nil, fmt.Errorf("不支持的填充方式: %s", opt.Padding)
	}

	return plaintext, nil
}

func Blowfish_test() {
	fmt.Println("\n---------- Blowfish测试 ----------")

	// 初始化参数
	key := []byte("blowfish-key12345")
	plaintext := []byte("这是一个Blowfish加密的明文测试。")

	// ECB模式测试
	fmt.Println("\n[ECB模式]")
	opt := &Options{
		Key:     key,
		Mode:    "ECB",
		Padding: "PKCS#7",
	}

	// 加密
	ciphertext, err := Blowfish_Encrypt(plaintext, opt)
	if err != nil {
		fmt.Printf("加密错误: %v\n", err)
		return
	}
	fmt.Printf("密文(Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err := Blowfish_Decrypt(ciphertext, opt)
	if err != nil {
		fmt.Printf("解密错误: %v\n", err)
		return
	}
	fmt.Printf("解密结果: %s\n", string(decrypted))
	fmt.Printf("解密是否成功: %v\n", bytes.Equal(plaintext, decrypted))

	// CBC模式测试
	fmt.Println("\n[CBC模式]")
	iv := []byte("12345678") // Blowfish块大小为8字节
	opt = &Options{
		Key:     key,
		Mode:    "CBC",
		Padding: "PKCS#7",
		Iv:      iv,
	}

	// 加密
	ciphertext, err = Blowfish_Encrypt(plaintext, opt)
	if err != nil {
		fmt.Printf("加密错误: %v\n", err)
		return
	}
	fmt.Printf("密文(Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err = Blowfish_Decrypt(ciphertext, opt)
	if err != nil {
		fmt.Printf("解密错误: %v\n", err)
		return
	}
	fmt.Printf("解密结果: %s\n", string(decrypted))
	fmt.Printf("解密是否成功: %v\n", bytes.Equal(plaintext, decrypted))

	// CTR模式测试
	fmt.Println("\n[CTR模式]")
	counter := []byte("87654321") // Blowfish块大小为8字节
	opt = &Options{
		Key:     key,
		Mode:    "CTR",
		Padding: "PKCS#7",
		Iv:      counter,
	}

	// 加密
	ciphertext, err = Blowfish_Encrypt(plaintext, opt)
	if err != nil {
		fmt.Printf("加密错误: %v\n", err)
		return
	}
	fmt.Printf("密文(Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err = Blowfish_Decrypt(ciphertext, opt)
	if err != nil {
		fmt.Printf("解密错误: %v\n", err)
		return
	}
	fmt.Printf("解密结果: %s\n", string(decrypted))
	fmt.Printf("解密是否成功: %v\n", bytes.Equal(plaintext, decrypted))
}

func Twofish_test() {
	fmt.Println("\n---------- Twofish测试 ----------")

	// 初始化参数
	key := []byte("twofish-key-16byte") // 刚好16字节密钥
	plaintext := []byte("这是一个Twofish加密的明文测试消息。")

	// ECB模式测试
	fmt.Println("\n[ECB模式]")
	opt := &Options{
		Key:     key,
		Mode:    "ECB",
		Padding: "PKCS#7",
	}

	// 加密
	ciphertext, err := Twofish_Encrypt(plaintext, opt)
	if err != nil {
		fmt.Printf("加密错误: %v\n", err)
		return
	}
	fmt.Printf("密文(Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err := Twofish_Decrypt(ciphertext, opt)
	if err != nil {
		fmt.Printf("解密错误: %v\n", err)
		return
	}
	fmt.Printf("解密结果: %s\n", string(decrypted))
	fmt.Printf("解密是否成功: %v\n", bytes.Equal(plaintext, decrypted))

	// CBC模式测试
	fmt.Println("\n[CBC模式]")
	iv := []byte("1234567890123456") // Twofish块大小为16字节
	opt = &Options{
		Key:     key,
		Mode:    "CBC",
		Padding: "PKCS#7",
		Iv:      iv,
	}

	// 加密
	ciphertext, err = Twofish_Encrypt(plaintext, opt)
	if err != nil {
		fmt.Printf("加密错误: %v\n", err)
		return
	}
	fmt.Printf("密文(Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err = Twofish_Decrypt(ciphertext, opt)
	if err != nil {
		fmt.Printf("解密错误: %v\n", err)
		return
	}
	fmt.Printf("解密结果: %s\n", string(decrypted))
	fmt.Printf("解密是否成功: %v\n", bytes.Equal(plaintext, decrypted))

	// CTR模式测试
	fmt.Println("\n[CTR模式]")
	counter := []byte("6543210987654321") // Twofish块大小为16字节
	opt = &Options{
		Key:     key,
		Mode:    "CTR",
		Padding: "PKCS#7",
		Iv:      counter,
	}

	// 加密
	ciphertext, err = Twofish_Encrypt(plaintext, opt)
	if err != nil {
		fmt.Printf("加密错误: %v\n", err)
		return
	}
	fmt.Printf("密文(Hex): %s\n", hex.EncodeToString(ciphertext))

	// 解密
	decrypted, err = Twofish_Decrypt(ciphertext, opt)
	if err != nil {
		fmt.Printf("解密错误: %v\n", err)
		return
	}
	fmt.Printf("解密结果: %s\n", string(decrypted))
	fmt.Printf("解密是否成功: %v\n", bytes.Equal(plaintext, decrypted))
}
