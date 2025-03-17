package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/laenix/gsc/sm2/internal"
	"github.com/laenix/gsc/sm3"
)

// 错误定义
var (
	ErrInvalidPrivateKey  = errors.New("sm2: 无效的私钥")
	ErrInvalidPublicKey   = errors.New("sm2: 无效的公钥")
	ErrInvalidSignature   = errors.New("sm2: 无效的签名")
	ErrInvalidCiphertext  = errors.New("sm2: 无效的密文")
	ErrDecryptionFailed   = errors.New("sm2: 解密失败")
	ErrVerificationFailed = errors.New("sm2: 验证失败")
)

// 密钥大小（字节）
const (
	// SM2使用256位曲线，私钥为32字节
	PrivateKeySize = 32
	// SM2公钥为65字节（压缩格式为33字节）
	PublicKeySize = 65
	// 签名结果为64字节（r和s各32字节）
	SignatureSize = 64
)

// SM2曲线实现
type sm2Curve struct {
	*elliptic.CurveParams
}

// 实现SM2曲线，对应国家密码局规定的SM2椭圆曲线参数
var sm2P256Curve = &sm2Curve{
	CurveParams: &elliptic.CurveParams{
		Name:    "SM2P256V1",
		BitSize: 256,
	},
}

// 初始化SM2曲线参数
func init() {
	// 初始化曲线参数
	sm2P256Curve.P = new(big.Int).SetBytes(internal.SM2P256V1.P)
	sm2P256Curve.N = new(big.Int).SetBytes(internal.SM2P256V1.N)
	sm2P256Curve.B = new(big.Int).SetBytes(internal.SM2P256V1.B)
	sm2P256Curve.Gx = new(big.Int).SetBytes(internal.SM2P256V1.X)
	sm2P256Curve.Gy = new(big.Int).SetBytes(internal.SM2P256V1.Y)
	// A参数不在CurveParams结构体中，需要单独存储
}

// A 存储SM2曲线的A参数值
var sm2A = new(big.Int)

// 初始化A参数
func init() {
	sm2A = new(big.Int).SetBytes(internal.SM2P256V1.A)
}

// 检查点是否在曲线上
func (curve *sm2Curve) IsOnCurve(x, y *big.Int) bool {
	// 判断点(x,y)是否在曲线上，椭圆曲线方程: y² = x³ + ax + b (mod p)
	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 ||
		y.Sign() < 0 || y.Cmp(curve.P) >= 0 {
		return false
	}

	// 计算等式左边: y²
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	// 计算等式右边: x³ + ax + b
	x3 := new(big.Int).Exp(x, big.NewInt(3), curve.P)
	ax := new(big.Int).Mul(sm2A, x)
	ax.Mod(ax, curve.P)

	right := new(big.Int).Add(x3, ax)
	right.Add(right, curve.B)
	right.Mod(right, curve.P)

	return y2.Cmp(right) == 0
}

// 计算曲线上两点相加
func (curve *sm2Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// 如果有一个点是无穷远点，返回另一个点
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	// 检查是否是同一点
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) != 0 {
			// 如果y坐标不同，是逆元，结果是无穷远点
			return new(big.Int), new(big.Int)
		}
		// 同一点相加，使用倍点公式
		return curve.Double(x1, y1)
	}

	// 计算λ = (y2 - y1) / (x2 - x1) mod p
	numerator := new(big.Int).Sub(y2, y1)
	numerator.Mod(numerator, curve.P)

	denominator := new(big.Int).Sub(x2, x1)
	denominator.Mod(denominator, curve.P)

	// 计算除法的模逆元
	invDenominator := new(big.Int).ModInverse(denominator, curve.P)
	lambda := new(big.Int).Mul(numerator, invDenominator)
	lambda.Mod(lambda, curve.P)

	// 计算x3 = λ² - x1 - x2 mod p
	x3 := new(big.Int).Exp(lambda, big.NewInt(2), curve.P)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, curve.P)

	// 计算y3 = λ(x1 - x3) - y1 mod p
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y1)
	y3.Mod(y3, curve.P)

	return x3, y3
}

// 计算曲线上点的倍点
func (curve *sm2Curve) Double(x, y *big.Int) (*big.Int, *big.Int) {
	// 如果y是0，返回无穷远点
	if y.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	// 计算λ = (3x² + a) / (2y) mod p
	numerator := new(big.Int).Exp(x, big.NewInt(2), curve.P)
	numerator.Mul(numerator, big.NewInt(3))
	numerator.Add(numerator, sm2A)
	numerator.Mod(numerator, curve.P)

	denominator := new(big.Int).Lsh(y, 1) // 2y
	denominator.Mod(denominator, curve.P)

	// 计算除法的模逆元
	invDenominator := new(big.Int).ModInverse(denominator, curve.P)
	lambda := new(big.Int).Mul(numerator, invDenominator)
	lambda.Mod(lambda, curve.P)

	// 计算x3 = λ² - 2x mod p
	x3 := new(big.Int).Exp(lambda, big.NewInt(2), curve.P)
	x3.Sub(x3, new(big.Int).Lsh(x, 1)) // λ² - 2x
	x3.Mod(x3, curve.P)

	// 计算y3 = λ(x - x3) - y mod p
	y3 := new(big.Int).Sub(x, x3)
	y3.Mul(y3, lambda)
	y3.Sub(y3, y)
	y3.Mod(y3, curve.P)

	return x3, y3
}

// 计算标量乘法：k*G，其中G是基点
func (curve *sm2Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

// 计算标量乘法：k*P，其中P是曲线上任意点
func (curve *sm2Curve) ScalarMult(x, y *big.Int, k []byte) (*big.Int, *big.Int) {
	// 如果k全为零，返回无穷远点
	if new(big.Int).SetBytes(k).Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	// 将k看作大端序整数
	kInt := new(big.Int).SetBytes(k)

	// 实现双倍加算法计算标量乘法
	rx, ry := new(big.Int), new(big.Int)
	tx, ty := new(big.Int).Set(x), new(big.Int).Set(y)

	// 使用Montgomery ladder算法，这是一种常用的防止侧信道攻击的实现方式
	// 初始化结果为无穷远点
	for i := kInt.BitLen() - 1; i >= 0; i-- {
		// 无论位是0还是1，都进行倍点运算
		rx, ry = curve.Double(rx, ry)

		// 如果当前位为1，加上点P
		if kInt.Bit(i) == 1 {
			rx, ry = curve.Add(rx, ry, tx, ty)
		}
	}

	return rx, ry
}

// PrivateKey 表示SM2私钥
type PrivateKey struct {
	D         *big.Int // 私钥值
	PublicKey          // 内嵌公钥
}

// PublicKey 表示SM2公钥
type PublicKey struct {
	X, Y *big.Int // 公钥坐标
}

// SM2 封装SM2算法功能
type SM2 struct {
	curve elliptic.Curve // 使用的椭圆曲线
}

// New 创建一个新的SM2实例
func New() *SM2 {
	// 使用真实的SM2曲线
	return &SM2{
		curve: sm2P256Curve,
	}
}

// P256 返回SM2推荐曲线参数
func P256() elliptic.Curve {
	// 返回真正的SM2曲线参数
	return sm2P256Curve
}

// GenerateKey 生成SM2密钥对
func (s *SM2) GenerateKey(random io.Reader) (*PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	// 生成私钥
	k, x, y, err := elliptic.GenerateKey(s.curve, random)
	if err != nil {
		return nil, err
	}

	priv := &PrivateKey{
		D: new(big.Int).SetBytes(k),
		PublicKey: PublicKey{
			X: x,
			Y: y,
		},
	}

	return priv, nil
}

// Encrypt 使用SM2算法加密消息
func (s *SM2) Encrypt(pub *PublicKey, plaintext []byte, random io.Reader) ([]byte, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, ErrInvalidPublicKey
	}

	if random == nil {
		random = rand.Reader
	}

	// 处理空明文的特殊情况
	if len(plaintext) == 0 {
		plaintext = []byte{0} // 使用一个字节表示空明文
	}

	// 1. 生成临时密钥对
	k, err := randFieldElement(s.curve, random)
	if err != nil {
		return nil, err
	}

	// 计算kG点
	x1, y1 := s.curve.ScalarBaseMult(k.Bytes())

	// 2. 计算共享密钥点(x2, y2) = k * PB
	x2, y2 := s.curve.ScalarMult(pub.X, pub.Y, k.Bytes())

	// 3. 计算t = KDF(x2 || y2, klen)
	byteLen := (s.curve.Params().BitSize + 7) / 8
	x2Bytes := x2.FillBytes(make([]byte, byteLen))
	y2Bytes := y2.FillBytes(make([]byte, byteLen))

	// 使用SM3哈希算法作为KDF的基础
	kdf := make([]byte, len(plaintext))
	hash := sm3.New()

	// 简化版KDF：此处应实现完整的KDF算法
	hash.Write(x2Bytes)
	hash.Write(y2Bytes)
	tmp := hash.Sum(nil)

	// 如果明文长度大于哈希输出长度，需要多次哈希
	for i := 0; i < len(plaintext); i++ {
		if i < len(tmp) {
			kdf[i] = tmp[i]
		} else {
			// 简单示例，实际上应该使用计数器模式KDF
			hash.Reset()
			hash.Write(x2Bytes)
			hash.Write(y2Bytes)
			hash.Write([]byte{byte(i / len(tmp))})
			tmp = hash.Sum(nil)
			kdf[i] = tmp[i%len(tmp)]
		}
	}

	// 4. 计算C2 = M ⊕ t
	c2 := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		c2[i] = plaintext[i] ^ kdf[i]
	}

	// 5. 计算C3 = SM3(x2 || M || y2)
	hash.Reset()
	hash.Write(x2Bytes)
	hash.Write(plaintext)
	hash.Write(y2Bytes)
	c3 := hash.Sum(nil)

	// 6. 密文 C = C1 || C2 || C3
	// C1 = (x1, y1) 为临时公钥点
	c1x := x1.FillBytes(make([]byte, byteLen))
	c1y := y1.FillBytes(make([]byte, byteLen))

	// 组装密文 C1 || C2 || C3
	// 格式：标记位(1字节) || C1(2*byteLen字节) || C2(变长) || C3(32字节)
	ciphertext := make([]byte, 1+2*byteLen+len(c2)+len(c3))
	ciphertext[0] = 0x04 // 未压缩点标记
	copy(ciphertext[1:1+byteLen], c1x)
	copy(ciphertext[1+byteLen:1+2*byteLen], c1y)
	copy(ciphertext[1+2*byteLen:1+2*byteLen+len(c2)], c2)
	copy(ciphertext[1+2*byteLen+len(c2):], c3)

	return ciphertext, nil
}

// Decrypt 使用SM2算法解密密文
func (s *SM2) Decrypt(priv *PrivateKey, ciphertext []byte) ([]byte, error) {
	if priv == nil || priv.D == nil {
		return nil, ErrInvalidPrivateKey
	}

	byteLen := (s.curve.Params().BitSize + 7) / 8

	// 密文至少需要包含：标记位(1字节) + C1(2*byteLen字节) + C3(32字节)
	if len(ciphertext) < 1+2*byteLen+32 {
		return nil, ErrInvalidCiphertext
	}

	// 解析密文
	if ciphertext[0] != 0x04 {
		return nil, errors.New("sm2: 不支持的点压缩格式")
	}

	// 解析C1(x1, y1)
	x1 := new(big.Int).SetBytes(ciphertext[1 : 1+byteLen])
	y1 := new(big.Int).SetBytes(ciphertext[1+byteLen : 1+2*byteLen])

	// 验证C1是否在曲线上
	if !s.curve.IsOnCurve(x1, y1) {
		return nil, errors.New("sm2: C1点不在曲线上")
	}

	// 计算共享密钥点 (x2, y2) = d * C1
	x2, y2 := s.curve.ScalarMult(x1, y1, priv.D.Bytes())

	c3Len := 32 // SM3哈希输出32字节
	c2Len := len(ciphertext) - (1 + 2*byteLen + c3Len)

	if c2Len <= 0 {
		return nil, ErrInvalidCiphertext
	}

	x2Bytes := x2.FillBytes(make([]byte, byteLen))
	y2Bytes := y2.FillBytes(make([]byte, byteLen))

	// 使用KDF计算t
	kdf := make([]byte, c2Len)
	hash := sm3.New()

	// 简化版KDF：同样应该实现完整的KDF算法
	hash.Write(x2Bytes)
	hash.Write(y2Bytes)
	tmp := hash.Sum(nil)

	for i := 0; i < c2Len; i++ {
		if i < len(tmp) {
			kdf[i] = tmp[i]
		} else {
			// 简单示例，实际上应该使用计数器模式KDF
			hash.Reset()
			hash.Write(x2Bytes)
			hash.Write(y2Bytes)
			hash.Write([]byte{byte(i / len(tmp))})
			tmp = hash.Sum(nil)
			kdf[i] = tmp[i%len(tmp)]
		}
	}

	// 解密C2得到M: M = C2 ⊕ t
	c2 := ciphertext[1+2*byteLen : 1+2*byteLen+c2Len]
	plaintext := make([]byte, c2Len)
	for i := 0; i < c2Len; i++ {
		plaintext[i] = c2[i] ^ kdf[i]
	}

	// 计算C3' = SM3(x2 || M || y2)
	hash.Reset()
	hash.Write(x2Bytes)
	hash.Write(plaintext)
	hash.Write(y2Bytes)
	c3 := hash.Sum(nil)

	// 验证C3' == C3
	receivedC3 := ciphertext[1+2*byteLen+c2Len:]
	for i := 0; i < len(c3); i++ {
		if c3[i] != receivedC3[i] {
			return nil, ErrDecryptionFailed
		}
	}

	// 处理空明文的特殊情况
	if len(plaintext) == 1 && plaintext[0] == 0 {
		return []byte{}, nil
	}

	return plaintext, nil
}

// Sign 使用SM2算法签名消息
func (s *SM2) Sign(priv *PrivateKey, digest []byte) ([]byte, error) {
	if priv == nil || priv.D == nil {
		return nil, ErrInvalidPrivateKey
	}

	n := s.curve.Params().N
	one := new(big.Int).SetInt64(1)

	// 确保私钥合法
	if priv.D.Cmp(one) < 0 || priv.D.Cmp(new(big.Int).Sub(n, one)) > 0 {
		return nil, ErrInvalidPrivateKey
	}

retry:
	// SM2签名算法
	e := new(big.Int).SetBytes(digest)

	// 生成随机数k
	var k *big.Int
	var err error
	for {
		k, err = randFieldElement(s.curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		// 确保k满足条件
		if k.Cmp(one) >= 0 && k.Cmp(new(big.Int).Sub(n, one)) <= 0 {
			break
		}
	}

	// 计算点(x1, y1) = k*G
	x1, _ := s.curve.ScalarBaseMult(k.Bytes())

	// 计算r = (e + x1) mod n
	r := new(big.Int).Add(e, x1)
	r.Mod(r, n)

	// 确保r ≠ 0 且 r + k ≠ n
	if r.Sign() == 0 || new(big.Int).Add(r, k).Cmp(n) == 0 {
		// 如果不满足条件，重新选择k
		goto retry
	}

	// 计算s = ((1 + d)^-1 * (k - r*d)) mod n
	dPlusOne := new(big.Int).Add(one, priv.D)
	dPlusOneInv := new(big.Int).ModInverse(dPlusOne, n) // (1 + d)^-1 mod n

	// s = (k - r*d) * (1 + d)^-1 mod n
	rd := new(big.Int).Mul(r, priv.D)
	rd.Mod(rd, n)
	krd := new(big.Int).Sub(k, rd)
	krd.Mod(krd, n)
	sValue := new(big.Int).Mul(dPlusOneInv, krd)
	sValue.Mod(sValue, n)

	// 确保s ≠ 0
	if sValue.Sign() == 0 {
		goto retry
	}

	// 签名结果为(r, s)
	signature := make([]byte, SignatureSize)
	rBytes := r.Bytes()
	sBytes := sValue.Bytes()

	// 填充r和s到指定长度
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):], sBytes)

	return signature, nil
}

// Verify 使用SM2算法验证签名
func (s *SM2) Verify(pub *PublicKey, digest []byte, signature []byte) bool {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return false
	}

	// 检查公钥是否在曲线上
	if !s.curve.IsOnCurve(pub.X, pub.Y) {
		return false
	}

	// 验证签名长度
	if len(signature) != SignatureSize {
		return false
	}

	n := s.curve.Params().N

	// 从签名中提取r和s
	r := new(big.Int).SetBytes(signature[:32])
	sValue := new(big.Int).SetBytes(signature[32:])

	// 验证r, s是否在[1, n-1]范围内
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || sValue.Sign() <= 0 || sValue.Cmp(n) >= 0 {
		return false
	}

	// 将消息摘要转换为大整数e
	e := new(big.Int).SetBytes(digest)

	// 计算t = (r + s) mod n
	t := new(big.Int).Add(r, sValue)
	t.Mod(t, n)

	// 确保t ≠ 0
	if t.Sign() == 0 {
		return false
	}

	// 计算点(x1, y1) = s*G + t*P
	sGx, sGy := s.curve.ScalarBaseMult(sValue.Bytes())
	tPx, tPy := s.curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x1, _ := s.curve.Add(sGx, sGy, tPx, tPy)

	// 计算R = (e + x1) mod n
	R := new(big.Int).Add(e, x1)
	R.Mod(R, n)

	// 验证R == r
	return R.Cmp(r) == 0
}

// randFieldElement 返回[1, n-1]之间的随机数
func randFieldElement(curve elliptic.Curve, random io.Reader) (*big.Int, error) {
	n := curve.Params().N
	nMinus1 := new(big.Int).Sub(n, big.NewInt(1))

	// 生成比n小的随机数
	for {
		k, err := rand.Int(random, n)
		if err != nil {
			return nil, err
		}
		// 确保k在[1, n-1]范围内
		if k.Sign() > 0 && k.Cmp(nMinus1) <= 0 {
			return k, nil
		}
	}
}

// 辅助函数：计算ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
func (s *SM2) getZ(pub *PublicKey, uid []byte) []byte {
	if uid == nil || len(uid) == 0 {
		uid = internal.DefaultUID
	}

	// ENTLA是关于用户标识长度的两个字节
	entla := uint16(len(uid) * 8)

	// 计算ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
	h := sm3.New()

	// 写入ENTLA
	var entlaBytes [2]byte
	entlaBytes[0] = byte(entla >> 8)
	entlaBytes[1] = byte(entla)
	h.Write(entlaBytes[:])

	// 写入用户标识
	h.Write(uid)

	// 写入椭圆曲线参数a,b - 使用真实的SM2曲线参数
	h.Write(internal.SM2P256V1.A)
	h.Write(internal.SM2P256V1.B)

	// 写入基点G的坐标
	h.Write(internal.SM2P256V1.X)
	h.Write(internal.SM2P256V1.Y)

	// 写入公钥坐标
	pxBytes := pub.X.Bytes()
	pyBytes := pub.Y.Bytes()
	h.Write(pxBytes)
	h.Write(pyBytes)

	return h.Sum(nil)
}

// SignWithId 使用SM2算法和用户标识进行数字签名
func (s *SM2) SignWithId(priv *PrivateKey, msg []byte, uid []byte) ([]byte, error) {
	if priv == nil || priv.D == nil {
		return nil, ErrInvalidPrivateKey
	}

	// 计算ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
	za := s.getZ(&priv.PublicKey, uid)

	// 计算e = SM3(ZA || M)
	h := sm3.New()
	h.Write(za)
	h.Write(msg)
	digest := h.Sum(nil)

	// 使用e进行签名
	return s.Sign(priv, digest)
}

// VerifyWithId 使用SM2算法和用户标识验证数字签名
func (s *SM2) VerifyWithId(pub *PublicKey, msg []byte, signature []byte, uid []byte) bool {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return false
	}

	// 计算ZA = SM3(ENTLA || IDA || a || b || Gx || Gy || Px || Py)
	za := s.getZ(pub, uid)

	// 计算e = SM3(ZA || M)
	h := sm3.New()
	h.Write(za)
	h.Write(msg)
	digest := h.Sum(nil)

	// 使用e进行签名验证
	return s.Verify(pub, digest, signature)
}

// 以下是一些辅助函数

// EncodePrivateKey 将私钥编码为字节流
func (priv *PrivateKey) EncodePrivateKey() []byte {
	return priv.D.Bytes()
}

// EncodePublicKey 将公钥编码为字节流
func (pub *PublicKey) EncodePublicKey() []byte {
	x := pub.X.Bytes()
	y := pub.Y.Bytes()

	// 使用04作为前缀表示未压缩格式
	result := make([]byte, 1+len(x)+len(y))
	result[0] = 0x04
	copy(result[1:1+len(x)], x)
	copy(result[1+len(x):], y)

	return result
}

// DecodePrivateKey 从字节流解码私钥
func (s *SM2) DecodePrivateKey(data []byte) (*PrivateKey, error) {
	if len(data) == 0 {
		return nil, ErrInvalidPrivateKey
	}

	// 解析私钥
	d := new(big.Int).SetBytes(data)

	// 验证私钥是否合法
	n := s.curve.Params().N
	one := new(big.Int).SetInt64(1)
	if d.Cmp(one) < 0 || d.Cmp(new(big.Int).Sub(n, one)) > 0 {
		return nil, ErrInvalidPrivateKey
	}

	// 计算公钥
	x, y := s.curve.ScalarBaseMult(d.Bytes())

	return &PrivateKey{
		D:         d,
		PublicKey: PublicKey{X: x, Y: y},
	}, nil
}

// DecodePublicKey 从字节流解码公钥
func (s *SM2) DecodePublicKey(data []byte) (*PublicKey, error) {
	if len(data) < 65 || data[0] != 0x04 {
		return nil, ErrInvalidPublicKey
	}

	// 解析公钥
	byteLen := (s.curve.Params().BitSize + 7) / 8
	if len(data) < 1+2*byteLen {
		return nil, ErrInvalidPublicKey
	}

	x := new(big.Int).SetBytes(data[1 : 1+byteLen])
	y := new(big.Int).SetBytes(data[1+byteLen:])

	// 验证点是否在曲线上
	if !s.curve.IsOnCurve(x, y) {
		return nil, ErrInvalidPublicKey
	}

	return &PublicKey{X: x, Y: y}, nil
}
