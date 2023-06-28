/*
Copyright 2020 The Board of Trustees of The Leland Stanford Junior University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package lzr

import (
	"strings"
)

var (
	handshakes     map[string]Handshake //所有handshake模块的[string]Handshake映射
	fingerprintMap map[string]int       //统计检测出的每种指纹的数量
)

type Handshake interface {
	GetData(dst string) []byte //获取该握手方式发送的第一个包中所含数据
	Verify(data string) string //根据回包数据返回识别的协议
}

// 添加新handshake模块
func AddHandshake(name string, h Handshake) {
	handshakes[name] = h
}

// 根据string获取对应的Handshake模块
func GetHandshake(name string) (Handshake, bool) {
	h, ok := handshakes[name]
	return h, ok
}

// 根据已识别的多个指纹结果 按优先级返回其中一项
func hiearchizeFingerprint(fingerprint string) string {

	req_handshakes := GetAllHandshakes()
	for _, h := range req_handshakes {
		if strings.Contains(fingerprint, h) {
			return h
		}
	}

	//优先级设置中没有识别出来的指纹 按照以下规则返回
	//!注意 这里是contains哦

	if strings.Contains(fingerprint, "ipp") {
		return "ipp"
	} else if strings.Contains(fingerprint, "kubernetes") {
		return "kubernetes"
	} else if strings.Contains(fingerprint, "dns") &&
		strings.Contains(fingerprint, "http") {
		return "http"
	} else if strings.Contains(fingerprint, "ssh") &&
		strings.Contains(fingerprint, "http") {
		return "http"
	} else if strings.Contains(fingerprint, "ftp") &&
		strings.Contains(fingerprint, "http") {
		return "http"
	} else if strings.Contains(fingerprint, "ftp") &&
		strings.Contains(fingerprint, "ssh") {
		return "ssh"
		//!probs tls with HTTPS text
	} else if strings.Contains(fingerprint, "tls") &&
		strings.Contains(fingerprint, "http") {
		return "tls"
	} else {
		return fingerprint
	}

}

// 使用所有handshake方式对该响应数据进行指纹识别
// !注意 由于目标可能在错误请求后返回带正确指纹的数据
// 因此采取发送用户指定handshake数据 使用所有handshake对响应进行识别的方式
func fingerprintResponse(data string) string {
	fingerprint := "" //所有指纹结果
	tfingerprint := ""
	multiprint := false //有多种指纹结果
	for _, hand := range handshakes {
		tfingerprint = hand.Verify(data)
		if tfingerprint != "" {
			//concat fingerprints together
			if fingerprint == "" {
				fingerprint += tfingerprint
			} else {
				multiprint = true
				fingerprint += ("-" + tfingerprint)
			}

		}
	}
	//如果有多种指纹结果 根据优先级取一种
	if multiprint {
		fingerprint = hiearchizeFingerprint(fingerprint)
	}
	if fingerprint == "" {
		fingerprint = "unknown"
	}
	//统计结果
	fingerprintMap[fingerprint] += 1
	return fingerprint
}

func GetFingerprints() map[string]int {
	return fingerprintMap
}

func init() {
	handshakes = make(map[string]Handshake)
	fingerprintMap = make(map[string]int)
}
