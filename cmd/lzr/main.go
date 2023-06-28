package main

import (
	"github.com/stanford-esrg/lzr/bin"
	_ "github.com/stanford-esrg/lzr/handshakes"
)

// main wraps the "true" main, bin.LZRMain()
// after importing all handshake modules
// to make importing self-defined modules conveniently
func main() {
	bin.LZRMain()
}
