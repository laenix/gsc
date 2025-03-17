package examples

import (
	"fmt"

	"github.com/laenix/gsc/aes"
	"github.com/laenix/gsc/des"
	"github.com/laenix/gsc/modes"
	"github.com/laenix/gsc/padding"
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

	// 定义要测试的模式和填充方式
	modes := []string{"ECB", "CBC", "CFB", "OFB", "CTR"}
	paddings := []string{"PKCS#7", "PKCS#5", "ISO7816", "Zero"}

	// DES密钥（8字节）
	key := []byte("12345678")
	// 初始化向量（8字节）
	iv := []byte("12345678")

	fmt.Println("\n=== DES 加密测试 ===")
	fmt.Printf("原文: %s\n", string(plaintext))

	for _, mode := range modes {
		for _, paddingType := range paddings {
			// 对于CFB和CTR模式，跳过填充测试
			if (mode == "CFB" || mode == "CTR") && paddingType != "PKCS#7" {
				continue
			}

			fmt.Printf("\n测试模式: %s, 填充方式: %s\n", mode, paddingType)

			opt := &Options{
				Key:       key,
				Iv:        iv,
				Mode:      mode,
				Padding:   paddingType,
				BlockSize: 8, // DES的块大小是8字节
			}

			// 加密
			ciphertext, err := DES_Encrypt(plaintext, opt)
			if err != nil {
				fmt.Printf("加密错误: %v\n", err)
				continue
			}
			fmt.Printf("密文(hex): %x\n", ciphertext)

			// 解密
			decrypted, err := DES_Decrypt(ciphertext, opt)
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
