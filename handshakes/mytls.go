package handshakes

import "github.com/stanford-esrg/lzr/handshakes/mytls"

func init() {
	mytls.RegisterHandshake()
}
