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

func HandleTimeout(opts *options, packet *packet_metadata, ipMeta *pState,
	timeoutQueue chan *packet_metadata, retransmitQueue chan *packet_metadata,
	writingQueue chan packet_metadata) {

	//所属连接已经处理完毕了
	if !ipMeta.metaContains(packet) {
		return
	}

	//send again with just data (not apart of handshake)
	//未超过重传次数 且该连接不是用于全响应探测
	if (packet.Counter < opts.RetransmitNum) && !packet.HyperACKtive {
		//记录重传次数
		packet.incrementCounter()

		//对于重传请求（第n次非连接请求的正式发包） 回ack 携带数据和之前相同
		if packet.ExpectedRToLZR == ACK || packet.ExpectedRToLZR == DATA {
			//将retransmitQ参数指定为timeoutQ 启动timeout计时
			//?不知道为啥第二次重传起就要使用timeout计时
			//一旦重传就设置PUSH
			SendAck(opts, packet, ipMeta, timeoutQueue, writingQueue, true, !(packet.Counter == 0), packet.ExpectedRToLZR)
		}

		//对于请求连接超时 重新发起连接
		if packet.ExpectedRToLZR == SYN_ACK {
			SendSyn(packet, ipMeta, timeoutQueue)
		}

	} else {
		//要么超过重传次数 继续握手或结束
		//要么是全响应探测
		handleExpired(opts, packet, ipMeta, timeoutQueue, writingQueue)
	}

}
