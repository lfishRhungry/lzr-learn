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

// 处理来自pcapIncoming或timeoutIncoming的包
// （参见HandlePcap和HandleTimeout）
// 该连接（包）可能需要再次进行指纹识别 并善后
func handleExpired(opts *options, packet *packet_metadata, ipMeta *pState,
	timeoutQueue chan *packet_metadata, writingQueue chan packet_metadata) {

	//如果该连接没有被停止 发送RST关闭该连接
	if !(packet.RST && !packet.ACK) {
		rst := constructRST(packet)
		_ = handle.WritePacketData(rst)
	}

	//获取当前正在进行的handshake类型序号
	handshakeNum := ipMeta.getHandshake(packet)

	//已经尝试完最后一种握手方式 或者该包是用于全响应探测
	if packet.HyperACKtive || (handshakeNum >= (len(opts.Handshakes) - 1)) {

		//将状态记录的handshake序号同步到该包
		packet.syncHandshakeNum(handshakeNum)

		//不是全响应探测回包的前提下
		// 要么该连接未到达accept data状态
		// 要么携带数据
		// 要么并没有强制尝试所有handshake
		//
		//?说明可能是之前未成功的handshake响应 记录
		if !packet.HyperACKtive && !(ForceAllHandshakes() && ipMeta.getData(packet) && len(packet.Data) == 0) {
			writingQueue <- *packet
		}

		//完毕 丢弃
		packet = ipMeta.remove(packet)

		//?这不知道有啥用
		if HyperACKtiveFiltering() {
			packet.HyperACKtive = true
			_ = ipMeta.remove(packet)
		}

	} else { //握手方式还未尝试完 尝试另一个握手方式

		//如果要尝试所有handshake，则对当前包识别指纹后记录结果
		if ForceAllHandshakes() && len(packet.Data) > 0 {
			packet.syncHandshakeNum(handshakeNum)
			writingQueue <- *packet
		}

		//进行下一类型handshake尝试
		packet.updatePacketFlow()
		ipMeta.incHandshake(packet)
		SendSyn(packet, ipMeta, timeoutQueue)

		//如果用户需要识别全响应主机 则应当在尝试第一次handshake时执行
		if handshakeNum == 0 && HyperACKtiveFiltering() {
			//对指定数量短暂端口进行探测
			for i := 0; i < getNumFilters(); i++ {
				highPortPacket := createFilterPacket(packet)
				SendSyn(highPortPacket, ipMeta, timeoutQueue)

				ipMeta.incHandshake(highPortPacket)                 //设置全响应探测包处于第2次handshake尝试阶段
				ipMeta.setHyperACKtiveStatus(highPortPacket)        //设置全响应探测包所属状态
				ipMeta.setParentSport(highPortPacket, packet.Sport) //设置全响应探测包父端口

				ipMeta.FinishProcessing(highPortPacket)
			}
		}

	}

}
