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
	"bufio"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	handle       *pcap.Handle
	snapshot_len int32 = 1024  //从pcap设备句柄中获取的每个packet的最大读取长度
	promiscuous  bool  = false //是否开启混杂模式 这里不需要
	err          error
	source_mac   string //本地主机mac
	dest_mac     string //网关mac
	QUEUE_SIZE   int32  = 100000000
)

func InitParams() {

	source_mac = getSourceMacAddr()
	dest_mac = getHostMacAddr()

}

// 创建并返回一个WritingQueue 用于将处理完毕需要进行记录的packet_metadata放入
func ConstructWritingQueue() chan packet_metadata {

	writingQueue := make(chan packet_metadata, QUEUE_SIZE)
	return writingQueue
}

// 创建整个工作流的输入Routine 并返回一个incoming通道
// 会将来自zmap或stdin的输入转换为对应的packet_metadata并放入incoming
func ConstructIncomingRoutine() chan *packet_metadata {

	incoming := make(chan *packet_metadata, QUEUE_SIZE)
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			//从标准输入中读取需要处理的任务
			input, err := reader.ReadString(byte('\n'))
			if err != nil && err == io.EOF {
				fmt.Fprintln(os.Stderr, "Finished Reading Input")
				close(incoming)
				return
			}

			var packet *packet_metadata
			if ReadZMap() {
				//如果是从zmap接续连接的情况
				//将zmap的输出转换为syn-ack类型packet_metadata回包
				packet = convertFromZMapToPacket(input)
			} else {
				//如果是需要lzr自行发syn探测包的情况
				//将目标信息转换为一个“假回包”（期望之后根据该回包发送对应的syn探测包）
				packet = convertFromInputListToPacket(input)
			}
			if packet == nil {
				continue
			}

			incoming <- packet
		}

	}()

	return incoming
}

// 创建并开始pcap工作流程 返回一个pcapIncoming
// 可以从中获取pcap捕获的已经转换为packet_metadata形式的包
func ConstructPcapRoutine(workers int) chan *packet_metadata {

	//该通道用于将gopacket转换好的packet_metadata放入 在他处处理
	pcapIncoming := make(chan *packet_metadata, QUEUE_SIZE)
	//该通道用于将pcap获取的原始gopacket放入 取出后准备转为packet_metadata
	pcapdQueue := make(chan *gopacket.Packet, QUEUE_SIZE)
	// 打开网卡设备获取句柄
	handle, err = pcap.OpenLive(getDevice(), snapshot_len, promiscuous, pcap.BlockForever) //1*time.Second)
	if err != nil {
		panic(err)
		// log.Fatal(err)
	}
	//编译并设置一个BPF来过滤掉zmap发送的syn包
	err := handle.SetBPFFilter("tcp[tcpflags] != tcp-syn")
	if err != nil {
		panic(err)
		// log.Fatal(err)
	}

	//从pcapdQueue中读取gopacket 将符合条件的转换为packet_metadata放入pcapIncoming
	//条件：完整的传输层tcp包
	//这里使用workers数量的goroutine来处理pcap得到的包
	for i := 0; i < workers; i++ {
		go func(i int) {
			for data := range pcapdQueue {
				packet := convertToPacketM(data)
				if packet == nil {
					continue
				}
				//如果网关mac没有设置 尝试从这里获取
				if dest_mac == "" {
					saveHostMacAddr(packet)
				}
				pcapIncoming <- packet
			}
		}(i)
	}
	//将从pcap中获取的gopacket放入pcapdQueue通道
	go func() {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for {
			pcapPacket, _ := packetSource.NextPacket()
			pcapdQueue <- &pcapPacket
		}
	}()

	return pcapIncoming

}

// 启动对timeoutQueue和retransmitQueue进行轮询处理的Routine 并返回timeoutIncoming通道
// 该Routine将timeoutQueue和retransmitQueue中到达超时时间点 且状态仍未更新的包（需要重传或重连接） 放入timeoutIncoming
func PollTimeoutRoutine(ipMeta *pState, timeoutQueue chan *packet_metadata, retransmitQueue chan *packet_metadata,
	timeoutT int, timeoutR int) chan *packet_metadata {

	TIMEOUT_T := time.Duration(timeoutT) * time.Second
	TIMEOUT_R := time.Duration(timeoutR) * time.Second

	timeoutIncoming := make(chan *packet_metadata, QUEUE_SIZE)

	//采用同样的流程根据各自超时设置 处理timeoutQueue和retransmitQueue
	timeoutAlg(ipMeta, timeoutQueue, timeoutIncoming, TIMEOUT_T)
	timeoutAlg(ipMeta, retransmitQueue, timeoutIncoming, TIMEOUT_R)

	return timeoutIncoming
}

// 超时算法
// 从queue中取出可能超时的包 到达其超时时间点后 如其状态还未更新 放入timeoutIncoming通道
// 这里的queue为retransmitQueue或timeoutQueue timeout为对应的超时时间
func timeoutAlg(ipMeta *pState, queue chan *packet_metadata, timeoutIncoming chan *packet_metadata,
	timeout time.Duration) {

	go func() {
		var tdif time.Duration
		for packet := range queue {
			//取出超时队列中第一个包后 等待至超时时间
			//（需要保证超时队列中的包按时间顺序放入并取出，且超时时间统一）
			tdif = time.Since(packet.Timestamp)
			if tdif < timeout {
				time.Sleep(timeout - tdif)
			}

			//查询在stateMap中为该包维护的状态
			p, ok := ipMeta.find(packet)
			if !ok {
				continue
			}
			//比较ExpectedRToLZR信息来观察状态是否变化
			if p.ExpectedRToLZR != packet.ExpectedRToLZR {
				//fmt.Println("state hasnt changed")
				continue
			} else {
				//fmt.Println("will deal with")
				//无变化 说明还需要进行处理
				timeoutIncoming <- packet
			}
		}
	}()
}

// 创建并返回retransmitQueue 用于可能需要重传其对应响应的所有回包
// （可能是除“假回包”外的任意已回复的回包）
// 之后会利用以下函数 在到达超时时间点时 检查该回包所属状态是否超时并处理
// PollTimeoutRoutine 和 timeoutAlg
func ConstructRetransmitQueue() chan *packet_metadata {

	retransmitQueue := make(chan *packet_metadata, QUEUE_SIZE)
	return retransmitQueue
}

// 创建并返回timeoutQueue
// 用于lzr自身发起tcp连接时，将已发送完syn包的“假回包”放入
// 之后会利用以下函数 在到达超时时间点时 检查该tcp连接请求是否超时并处理
// PollTimeoutRoutine 和 timeoutAlg
func ConstructTimeoutQueue() chan *packet_metadata {

	timeoutQueue := make(chan *packet_metadata, QUEUE_SIZE)
	return timeoutQueue
}
