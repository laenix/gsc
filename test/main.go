package main

import "fmt"

func main() {
	fmt.Println("=== 开始测试CTR模式 ===")
	TestCTR()

	fmt.Println("\n=== 开始测试GCM模式 ===")
	TestGCM()

	fmt.Println("\n=== 开始测试DES算法 ===")
	TestDES()
}
