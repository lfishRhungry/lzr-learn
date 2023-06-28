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
// 该文件中包含回复ack类型包时用到的功能函数
package lzr

import (
	"log"
)

// 根据设置 针对syn-ack回包来响应ack 并放入retransmitQueue
// 如无状态会新建
// 完毕后不会标记处理结束
// @param retransmitQueue 根据计时需要 可以使用 timeoutQ 或 retransmitQ
func SendAck(opts *options, synack *packet_metadata, ipMeta *pState,
	retransmitQueue chan *packet_metadata, writingQueue chan packet_metadata,
	toACK bool, toPUSH bool, expectedResponse string) {

	//如果syn-ack是零窗口 不用回 记录
	if synack.windowZero() {
		writingQueue <- *synack
		return
	}

	//根据syn-ack所属状态中正在进行的handshake类型 获取相应的payload和原始ack
	handshakeNum := ipMeta.getHandshake(synack)
	handshake, _ := GetHandshake(opts.Handshakes[handshakeNum])
	ack, payload := constructData(handshake, synack, toACK, toPUSH) //true, false )
	//修改syn-ack信息并更新所属状态
	synack.updateResponse(expectedResponse) //期望得到ACK回复 证明服务器对数据进行给了确认
	synack.updateResponseL(payload)
	synack.updateTimestamp()
	ipMeta.update(synack) //在没有状态的情况下新建状态
	err := handle.WritePacketData(ack)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	//随时更新timestamp
	synack.updateTimestamp()

	//!这里的retransmitQueue可能是retransmitQueue
	//该syn-ack包经过以上发送ack的处理后
	//可能无法收到数据确认
	//因此将更新后的syn-ack加入retransmitQueue
	//在到达重传时间点后 会检查是否需要重传
	retransmitQueue <- synack
}
