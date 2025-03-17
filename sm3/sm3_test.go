package sm3

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type sm3Test struct {
	in  string // 输入数据
	out string // 期望的哈希值（十六进制字符串）
}

// 测试向量
// 参考中国国家标准GB/T 32905-2016文档中的测试向量
var golden = []sm3Test{
	// 示例1: 空字符串
	{"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
	// 示例2: "abc"字符串
	{"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
	// 示例3: 长度为64字节的字符串
	{"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd", "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
}

// 测试Sum函数
func TestSum(t *testing.T) {
	for i, test := range golden {
		data := []byte(test.in)
		sum := Sum(data)
		hex := hex.EncodeToString(sum[:])
		if hex != test.out {
			t.Errorf("Sum test #%d failed. Expected: %s, got: %s", i, test.out, hex)
		}
	}
}

// 测试New和Write方法
func TestNew(t *testing.T) {
	for i, test := range golden {
		h := New()
		h.Write([]byte(test.in))
		sum := h.Sum(nil)
		hex := hex.EncodeToString(sum)
		if hex != test.out {
			t.Errorf("New+Write+Sum test #%d failed. Expected: %s, got: %s", i, test.out, hex)
		}
	}
}

// 测试分块写入
func TestBlockWrites(t *testing.T) {
	// 选择一个长度超过块大小的测试数据
	longText := bytes.Repeat([]byte("abcdefgh"), 100) // 800字节

	// 一次性写入的结果
	h1 := New()
	h1.Write(longText)
	sum1 := h1.Sum(nil)

	// 分块写入的结果
	h2 := New()
	chunkSize := 40 // 任意小于块大小的值
	for i := 0; i < len(longText); i += chunkSize {
		end := i + chunkSize
		if end > len(longText) {
			end = len(longText)
		}
		h2.Write(longText[i:end])
	}
	sum2 := h2.Sum(nil)

	// 两种方式应得到相同的结果
	if !bytes.Equal(sum1, sum2) {
		t.Errorf("Block write test failed. Single write: %x, multiple writes: %x", sum1, sum2)
	}
}

// 测试Reset方法
func TestReset(t *testing.T) {
	h1 := New()
	h1.Write([]byte("abc"))
	sum1 := h1.Sum(nil)

	h1.Reset()
	h1.Write([]byte("abc"))
	sum2 := h1.Sum(nil)

	if !bytes.Equal(sum1, sum2) {
		t.Errorf("Reset test failed. Before: %x, after: %x", sum1, sum2)
	}
}

// 基准测试
func BenchmarkHash1K(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 1024) // 1KB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(data)
	}
	b.SetBytes(1024)
}

func BenchmarkHash8K(b *testing.B) {
	data := bytes.Repeat([]byte("a"), 8192) // 8KB
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(data)
	}
	b.SetBytes(8192)
}
