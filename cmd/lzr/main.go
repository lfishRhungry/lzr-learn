package main

import (
	"github.com/stanford-esrg/lzr/bin"
	_ "github.com/stanford-esrg/lzr/handshakes"
)

// main包裹真正的LZRMain来运行核心框架
// 此处引入的handshakes会在运行时自动加载
func main() {
	bin.LZRMain()
}
