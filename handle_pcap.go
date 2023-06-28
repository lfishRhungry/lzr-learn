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
	"log"
)

// 使用RST响应关闭该连接 并取消状态维护
// 根据write决定是否记录结果
// 根据ackingFirewall决定是否标记为全响应主机
func closeConnection(packet *packet_metadata, ipMeta *pState, writingQueue chan packet_metadata, write bool, ackingFirewall bool) {

	//发送RST关闭连接
	rst := constructRST(packet)
	err := handle.WritePacketData(rst)
	if err != nil {
		log.Fatal(err)
	}
	//取消状态维护
	packet = ipMeta.remove(packet)
	if write {
		packet.setHyperACKtive(ackingFirewall)
		writingQueue <- *packet
	}
}

// 处理从pcap中获取的正在维护状态的包
func HandlePcap(opts *options, packet *packet_metadata, ipMeta *pState, timeoutQueue chan *packet_metadata,
	retransmitQueue chan *packet_metadata, writingQueue chan packet_metadata) {

	//确认该包是针对其中一个维护状态的一个回包
	verified := ipMeta.verifyScanningIP(packet)
	if !verified {
		packet.incrementCounter()
		packet.updateTimestamp()
		packet.validationFail()
		//不是维护状态的话
		//以防万一 将其放入timeoutQueue
		timeoutQueue <- packet
		return
	}

	isHyperACKtive := ipMeta.getHyperACKtiveStatus(packet) //该状态是否属于全响应类型
	handshakeNum := ipMeta.getHandshake(packet)            //该状态正在进行的握手序号

	//ack 更新状态
	if (!packet.SYN) && packet.ACK {
		ipMeta.updateAck(packet)
	}

	//返回了数据 则关闭该连接 识别指纹并记录结果
	if len(packet.Data) > 0 {

		//更新维护状态
		packet.updateResponse(DATA) //已经进入数据交互状态
		ipMeta.updateData(packet)   //此时已经有状态 但是用该packet更新状态

		// 需要强制所有handshake 可能要继续尝试 交给handleExpired
		if ForceAllHandshakes() {
			handleExpired(opts, packet, ipMeta, timeoutQueue, writingQueue)
		} else { //否则直接记录
			//将正在进行的handshake序号保存到该包
			packet.syncHandshakeNum(handshakeNum)
			//关闭连接并记录结果（记录结果时会识别指纹）
			closeConnection(packet, ipMeta, writingQueue, true, isHyperACKtive)
		}

	} else if packet.RST || packet.FIN {

		//未返回数据 且目标要关闭连接 则可能需要继续尝试handshake
		handleExpired(opts, packet, ipMeta, timeoutQueue, writingQueue)

	} else if HyperACKtiveFiltering() && handshakeNum == 1 && !isHyperACKtive && ipMeta.getEphemeralRespNum(packet) > getNumFilters() {
		//条件限制如下：
		//1.用户需要检测全响应
		//2.处于第二次尝试handshakeNum 说明第一次尝试时 全响应探测包已经发出
		//3.本连接不是用来做全响应探测的
		//4.针对本连接的全响应探测响应数量超过了阈值
		//
		//参见handleExpired函数判断该主机存在全响应 记录
		closeConnection(packet, ipMeta, writingQueue, true, true)

	} else if (!packet.SYN) && packet.ACK {

		//ack类型 不是全响应主机
		//说明是确认了数据进入accept data状态 但未返回数据
		packet.updateResponse(DATA)
		packet.updateTimestamp()
		ipMeta.update(packet)

		//可能需要进行PUSH重传
		timeoutQueue <- packet

	} else if packet.SYN && packet.ACK {

		//需要进行全响应探测 且该包状态处于第2次尝试握手期间
		//说明全响应探测已经发出 参见handleExpired
		if handshakeNum == 1 && HyperACKtiveFiltering() {

			//该连接就是为了探测全响应而建立的
			if isHyperACKtive {
				//增加父端口连接的短暂端口响应次数 关闭连接并记录
				parentSport := ipMeta.getParentSport(packet)
				ipMeta.incEphemeralResp(packet, parentSport)
				closeConnection(packet, ipMeta, writingQueue, false, isHyperACKtive)
				return
			} else {
				//该连接在进行第二次尝试握手时 返回的syn-ack
				//这里不知道为什么也要增加全响应数量
				ipMeta.incEphemeralResp(packet, packet.Sport)
			}
		}

		//对每个syn-ack都回复ack
		toACK := true
		toPUSH := false
		SendAck(opts, packet, ipMeta, retransmitQueue, writingQueue, toACK, toPUSH, ACK)

	}
}
