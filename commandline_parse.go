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
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	filename               *string
	sendSYNs               *bool
	sourceIP               *string
	device                 *string
	mac                    *string
	debug                  *bool
	haf                    *int  //用户指定 过滤全响应主机时 需要测试的端口数量
	pushDOnly              *bool //使用push
	forceAllHandshakes     *bool //用户指定要进行所有握手
	feedZGrab              *bool //输出zgrab可用结果
	workers                *int  //每个通道工作的goroutine数量
	timeout                *int  //lzr发起tcp请求后的超时时长
	retransmitSec          *int  //对发包无响应 需要重传的最少时长
	retransmitNum          *int  //最多重传几次
	cpuprofile             *string
	memprofile             *string
	handshake              *string //用户指定的handshake参数字符串
	priorityFingerprint    *string
	priorityFingerprintArr []string
	handshakeArr           []string //将用户指定的handshake拆分成的handshake字符串切片
)

type options struct {
	Filename            string
	SendSYNs            bool
	SourceIP            string
	Device              string
	Mac                 string
	Debug               bool
	Haf                 int
	PushDOnly           bool
	ForceAllHandshakes  bool
	FeedZGrab           bool
	Workers             int
	Timeout             int
	RetransmitSec       int
	RetransmitNum       int
	CPUProfile          string
	MemProfile          string
	Handshakes          []string //将用户指定的handshake拆分成的handshake字符串切片
	PriorityFingerprint []string //多指纹成立时 用户指定的指纹结果优先级顺序
}

// Basic flag declarations are available for string, integer, and boolean options.
func init() {
	fname := "default_" + string(time.Now().Format("20060102150405")) + ".json"
	filename = flag.String("f", fname, "json results output file name, use '-' for standard output")
	sendSYNs = flag.Bool("sendSYNs", false, "will read input from stdin containing a newline-delimited list of ip:port")
	sourceIP = flag.String("sourceIP", "", "source IP to send syn packets with (if using sendSYNs flag)")
	device = flag.String("sendInterface", "ens8", "network interface to send packets on")
	mac = flag.String("gatewayMac", "", "gateway Mac Address in format xx:xx:xx:xx:xx:xx")
	debug = flag.Bool("d", false, "debug printing on")
	haf = flag.Int("haf", 0, "number of random ephemeral probes to send to filter ACKing firewalls")
	pushDOnly = flag.Bool("pushDataOnly", false, "Don't attach data to ack but rather to push only")
	forceAllHandshakes = flag.Bool("forceAllHandshakes", false, "Complete all handshakes even if data is returned early on. This also turns off HyperACKtive filtering.")
	feedZGrab = flag.Bool("feedZGrab", false, "send to zgrab ip and fingerprint")
	workers = flag.Int("w", 1, "number of worker threads for each channel")
	timeout = flag.Int("t", 5, "number of seconds to wait in timeout queue for last retransmission")
	retransmitSec = flag.Int("rt", 1, "number of seconds until re-transmitting packet")
	retransmitNum = flag.Int("rn", 1, "number of data packets to re-transmit")
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	memprofile = flag.String("memprofile", "", "write memory profile to this file")
	handshake = flag.String("handshakes", "http", "handshakes to scan with")
	priorityFingerprint = flag.String("priorityFingerprint", "", "fingerprint to prioritize when multiple match")
}

// 检查用户指定的handshake是否都有相应的模块，完毕后拆分为handshake字符串数组放入optHandshakes
func checkAndParse(handshake *string, optHandshakes *[]string) ([]string, bool) {

	if *handshake == "" {
		return nil, true
	}

	if !strings.Contains(*handshake, ",") {

		_, ok := GetHandshake(*handshake)

		if !ok {
			fmt.Fprintln(os.Stderr, "--Handshake not found:", *handshake)
			return nil, false
		}

		(*optHandshakes)[0] = *handshake
	} else {
		i := 0
		for _, h := range strings.Split(*handshake, ",") {

			_, ok := GetHandshake(h)
			if !ok {
				fmt.Fprintln(os.Stderr, "--Handshake not found:", h)
				return nil, false
			}

			(*optHandshakes)[i] = h
			i += 1
		}
	}
	return *optHandshakes, true

}

func Parse() (*options, bool) {

	flag.Parse()
	opt := &options{
		Filename:            *filename,
		SendSYNs:            *sendSYNs,
		Debug:               *debug,
		Device:              *device,
		Mac:                 *mac,
		Haf:                 *haf,
		FeedZGrab:           *feedZGrab,
		PushDOnly:           *pushDOnly,
		ForceAllHandshakes:  *forceAllHandshakes,
		Workers:             *workers,
		Timeout:             *timeout,
		RetransmitSec:       *retransmitSec,
		RetransmitNum:       *retransmitNum,
		CPUProfile:          *cpuprofile,
		MemProfile:          *memprofile,
		Handshakes:          make([]string, strings.Count(*handshake, ",")+1),
		PriorityFingerprint: make([]string, strings.Count(*priorityFingerprint, ",")+1),
	}

	success := false
	handshakeArr, success = checkAndParse(handshake, &(opt.Handshakes))
	if !success {
		return nil, false
	}

	priorityFingerprintArr, success = checkAndParse(priorityFingerprint, &(opt.PriorityFingerprint))
	if !success {
		return nil, false
	}

	if *forceAllHandshakes {
		*haf = 0
	}

	fmt.Fprintln(os.Stderr, "++Writing results to file:", *filename)
	fmt.Fprintln(os.Stderr, "++Handshakes:", *handshake)
	if *sendSYNs {
		fmt.Fprintln(os.Stderr, "++Sending SYNs")
	}
	if *sourceIP != "" {
		fmt.Fprintln(os.Stderr, "++Using SourceIP:", *sendSYNs)
	}
	if *device != "ens8" {
		fmt.Fprintln(os.Stderr, "++Using Sending Interface:", *device)
	}
	if *mac != "" {
		fmt.Fprintln(os.Stderr, "++Using Gateway Mac:", *mac)
	}
	if *priorityFingerprint != "" {
		fmt.Fprintln(os.Stderr, "++Prioritizing Fingerprints:", *priorityFingerprint)
	}
	if *memprofile != "" {
		fmt.Fprintln(os.Stderr, "++Writing memprofile to file:", *memprofile)
	}
	if *cpuprofile != "" {
		fmt.Fprintln(os.Stderr, "++Writing cpuprofile to file:", *cpuprofile)
	}
	if *debug {
		fmt.Fprintln(os.Stderr, "++Debug turned on")
	}
	if *haf > 0 {
		fmt.Fprintln(os.Stderr, "++Sending ", *haf, " number of filtering packets")
	}
	if *feedZGrab {
		fmt.Fprintln(os.Stderr, "++Feeding ZGrab with fingerprints")
	}
	if *pushDOnly {
		fmt.Fprintln(os.Stderr, "++Sending Data only with Push Flag (not in ack)")
	}
	if *forceAllHandshakes {
		fmt.Fprintln(os.Stderr, "++Force completing all handshakes")
	}
	fmt.Fprintln(os.Stderr, "++Worker threads:", *workers)
	fmt.Fprintln(os.Stderr, "++Timeout Interval (s):", *timeout)
	fmt.Fprintln(os.Stderr, "++Retransmit Interval (s):", *retransmitSec)
	fmt.Fprintln(os.Stderr, "++Number of Retransmitions:", *retransmitNum)
	//fmt.Fprintln(os.Stderr,"port:", *port)
	return opt, true
}

func DebugOn() bool {
	return *debug
}

func FeedZGrab() bool {
	return *feedZGrab
}

func HyperACKtiveFiltering() bool {
	return *haf != 0
}

func ReadZMap() bool {
	return !*sendSYNs
}

func getNumFilters() int {
	return *haf
}

func getSourceIP() string {
	return *sourceIP
}

func getDevice() string {
	return *device
}

// 获取命令行参数中设置的网关mac地址
// 用来构造向外发送的packet
func getHostMacAddr() string {
	return *mac
}

func PushDOnly() bool {
	return *pushDOnly
}

// 用户是否指定要进行所有握手
func ForceAllHandshakes() bool {
	return *forceAllHandshakes
}

// 获取（优先级）handshakes列表
func GetAllHandshakes() []string {

	if priorityFingerprintArr != nil {
		return priorityFingerprintArr
	}
	return handshakeArr
}

// 获取用户指定的handshake数量
func NumHandshakes() int {
	return len(handshakeArr)
}
