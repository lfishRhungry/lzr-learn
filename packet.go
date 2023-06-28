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
	"encoding/json"
	"log"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"fmt"
)

// 这里定义几个关于ExpectedRToLZR的状态
var (
	ACK     string = "ack"  //已发送携带数据的ack 期望对方确认数据
	SYN_ACK string = "sa"   //已发送syn探测 期望对方同意建立连接
	DATA    string = "data" //对方已确认过数据 进入正常数据交互阶段
)

// 实际存储packet状态的结构
type packet_state struct {
	HandshakeNum     int               //正在进行的handshake类型序号
	Ack              bool              //该状态已到达accept data
	Data             bool              //是否返回了data
	HyperACKtive     bool              //该状态是用来探测全响应的
	EphemeralFilters []packet_metadata //过滤全响应主机时使用，保存用来在该连接中进行随机短暂端口检测的packet_metadata
	EphemeralRespNum int               //全响应探测时，已经响应的数量
	ParentSport      int               //用于过滤全响应主机时收到的包，标识该过滤检测是用来协助探测ParentSport时使用的
	Packet           *packet_metadata  //保存在最后一个回包信息
}

// 存储packet具体数据
type packet_metadata struct {
	Smac    string `json:"-"`
	Dmac    string `json:"-"`
	Saddr   string `json:"saddr"`
	Daddr   string `json:"daddr"`
	Sport   int    `json:"sport"`
	Dport   int    `json:"dport"`
	Seqnum  int    `json:"seqnum"`
	Acknum  int    `json:"acknum"`
	Window  int    `json:"window"`
	TTL     uint8  `json:"ttl"`
	Counter int    //针对该回包已经响应的次数（不能超过RetransmitNum）

	ACK     bool //该packet是否包含ack flag
	ACKed   bool //该packet是否被acked
	SYN     bool
	RST     bool
	FIN     bool
	PUSH    bool
	ValFail bool `json:"-"` //验证该回包是否属于已维护连接时失败

	HandshakeNum   int       //该回包是使用handshake序号为HandshakeNum时收到的
	Fingerprint    string    `json:"fingerprint,omitempty"` //保存从该packet中检测到的指纹
	Timestamp      time.Time //最后一次处理该回包或其状态时的时间
	LZRResponseL   int       `json:"-"`                        //针对该回包作出的响应中 所含数据内容长度
	ExpectedRToLZR string    `json:"expectedRToLZR,omitempty"` //该回包所属状态所期望再次收到的回包类型
	Data           string    `json:"data,omitempty"`           //该回包内数据
	//!该回包正在被处理（从收到回包到做出响应）
	//所有刚生成的回包（zmap包、假回包、pcap包）都会标记为正在处理 然后放入incoming
	//直到从incoming中取出 经过SendACK或SendSYN后 第一次标记处理完毕
	Processing   bool `json:"-"`                        //该回包所属状态正在被处理
	HyperACKtive bool `json:"ackingFirewall,omitempty"` //该回包是属于全响应探测连接的
}

// 整合各层数据形成packet_metadata
func ReadLayers(ip *layers.IPv4, tcp *layers.TCP, eth *layers.Ethernet) *packet_metadata {

	packet := &packet_metadata{
		Smac:         eth.SrcMAC.String(),
		Dmac:         eth.DstMAC.String(),
		Saddr:        ip.SrcIP.String(),
		Daddr:        ip.DstIP.String(),
		TTL:          ip.TTL,
		Sport:        int(tcp.SrcPort),
		Dport:        int(tcp.DstPort),
		Seqnum:       int(tcp.Seq),
		Acknum:       int(tcp.Ack),
		Window:       int(tcp.Window),
		ACK:          tcp.ACK,
		SYN:          tcp.SYN,
		RST:          tcp.RST,
		FIN:          tcp.FIN,
		PUSH:         tcp.PSH,
		Data:         string(tcp.Payload),
		Timestamp:    time.Now(),
		Counter:      0,
		Processing:   true, //!标记为正在处理
		HandshakeNum: 0,
	}
	return packet
}

// 将gopacket转换为packet_metadata
func convertToPacketM(packet *gopacket.Packet) *packet_metadata {

	tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
	//确保是传输层的tcp类型包
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
		//确保有IP头
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)

			ethLayer := (*packet).Layer(layers.LayerTypeEthernet)
			if ethLayer != nil {
				eth, _ := ethLayer.(*layers.Ethernet)
				metapacket := ReadLayers(ip, tcp, eth)
				return metapacket
			}
		}
	}
	return nil
}

// 将zmap扫描结果输出的特定格式字符串（标识一个synack包）
// 转换为一个虚拟已接收的packet_metadata
func convertFromZMapToPacket(input string) *packet_metadata {

	synack := &packet_metadata{}
	//输入数据应当包括 ip,sequence number, acknumber,windowsize, sport, dport
	//直接使用带tag的结构体与json数据的对应关系来转换
	err := json.Unmarshal([]byte(input), synack)
	//!标记为正在处理
	synack.Processing = true
	//标识其为syn-ack类型
	synack.SYN = true
	synack.ACK = true
	if err != nil {
		log.Fatal(err)
		return nil
	}
	return synack
}

// 根据目标ip和端口 制作一个不存在的“假回包”
// 用于放入WritingQueue中 待取出后使用以下函数构造真正的syn包准备发出
// func constructSYN(p *packet_metadata) []byte
func convertFromInputListToPacket(input string) *packet_metadata {

	rand.Seed(time.Now().UTC().UnixNano())

	input = strings.TrimSuffix(input, "\n")
	s := strings.Split(input, ":")
	if len(s) != 2 {
		panic("Error parsing input list")
	}

	saddr, sport_s := s[0], s[1]
	sport, err := strconv.Atoi(sport_s)
	if err != nil {
		panic(err)
	}

	if getHostMacAddr() == "" {
		panic("Gateway Mac Address required")
	}

	if getSourceIP() == "" {
		panic("Source IP required")
	}

	//!注意 由于构造的是回包，这里source和dest作了交换
	//!同时 设置的seq ack window 之后会直接复制到引发的syn包
	syn := &packet_metadata{
		Smac:           source_mac,
		Dmac:           getHostMacAddr(),
		Saddr:          saddr,
		Daddr:          getSourceIP(),
		Dport:          randInt(32768, 61000), //外发syn包时随机构造源端口
		Sport:          sport,
		Seqnum:         int(rand.Uint32()), //随机tcp序号
		Acknum:         0,
		Window:         65535,
		SYN:            true,
		Timestamp:      time.Now(),
		Counter:        0,
		Processing:     true, //标记为正在处理
		HandshakeNum:   0,
		ExpectedRToLZR: SYN_ACK, //期望得到syn-ack回包 准确来说 希望发送syn包后得到syn-ack
	}

	return syn
}

func randInt(min int, max int) int {
	return min + rand.Intn(max-min)
}

// 根据给定packet 构造一个“假回包”用来引发对目标主机高端随机端口检测
func createFilterPacket(packet *packet_metadata) *packet_metadata {

	rand.Seed(time.Now().UTC().UnixNano())
	packetFilter := &packet_metadata{
		Smac:           packet.Smac,
		Dmac:           packet.Dmac,
		Saddr:          packet.Saddr,
		Daddr:          packet.Daddr,
		Dport:          int(math.Mod(float64(packet.Dport), 65535) + 1), //!“源端口”要更改
		Sport:          randInt(32768, 61000),                           //!“目标端口”在高处随机
		Seqnum:         int(rand.Uint32()),
		Acknum:         0,
		Window:         packet.Window,
		SYN:            true,
		Timestamp:      time.Now(),
		Counter:        0,
		Processing:     true,
		HandshakeNum:   0,
		HyperACKtive:   true,
		ExpectedRToLZR: SYN_ACK,
	}
	return packetFilter
}

// 将向外发送源端口随机修改 用来发送 同时更新采用的handshakes序号
func (packet *packet_metadata) updatePacketFlow() {
	newsrcprt := math.Mod(float64(packet.Dport), 65535) + 1
	packet.Dport = int(newsrcprt) //!回包的目的端口是发送源端口
	packet.HandshakeNum += 1
	packet.Counter = 0
	packet.ExpectedRToLZR = SYN_ACK
	packet.Seqnum = packet.Acknum
	packet.Acknum = 0
	packet.Data = ""
	packet.Fingerprint = ""
	packet.SYN = false
	packet.ACK = false
	packet.PUSH = false
	packet.RST = false
	packet.FIN = false
}

// 检查是否是零窗口的syn-ack包
func (packet *packet_metadata) windowZero() bool {
	if packet.Window == 0 && packet.SYN && packet.ACK {
		return true
	}
	return false
}

// 将状态中存储的handshake类型序号同步到该包中保存
func (packet *packet_metadata) syncHandshakeNum(h int) {

	packet.HandshakeNum = h

}

// 获取握手次数
func (packet *packet_metadata) getHandshakeNum() int {
	return packet.HandshakeNum

}

// 更新期望的回复
func (packet *packet_metadata) updateResponse(state string) {

	packet.ExpectedRToLZR = state

}

func (packet *packet_metadata) updateResponseL(data []byte) {

	packet.LZRResponseL = len(data)

}
func (packet *packet_metadata) incrementCounter() {

	packet.Counter += 1

}

func (packet *packet_metadata) updateTimestamp() {

	packet.Timestamp = time.Now()

}

// 标记该packet_metadata处于正在处理状态
func (packet *packet_metadata) startProcessing() {

	packet.Processing = true

}

// 标记该packet_metadata已经不处于正在处理状态
func (packet *packet_metadata) finishedProcessing() {

	packet.Processing = false

}

func (packet *packet_metadata) updateData(payload string) {

	packet.Data = payload

}

// 标记packet并不是已维护状态的回包
func (packet *packet_metadata) validationFail() {

	packet.ValFail = true

}

func (packet *packet_metadata) getValidationFail() bool {

	return packet.ValFail

}

func (packet *packet_metadata) getSourceMac() string {

	return packet.Smac

}

// 使用packet内部指定的handshake对包内数据进行指纹识别 并保存在packet_metadata中
func (packet *packet_metadata) fingerprintData() {

	packet.Fingerprint = fingerprintResponse(packet.Data)

}

func (packet *packet_metadata) setHyperACKtive(ackingFirewall bool) {

	packet.HyperACKtive = ackingFirewall

}
