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
// 该文件中包含发送syn类型包时用到的功能函数
package lzr

// 根据提供的“回包” 构造并发送syn探测包 并放入timeoutQueue
// 如无状态会新建
// 完毕后标记处理结束
func SendSyn(packet *packet_metadata, ipMeta *pState, timeoutQueue chan *packet_metadata) {
	//更新回包信息及其所属状态
	packet.updateResponse(SYN_ACK)
	packet.updateTimestamp()
	ipMeta.update(packet) //在没有状态的情况下新建状态
	//构造syn包并发送
	syn := constructSYN(packet)
	err := handle.WritePacketData(syn)
	if err != nil {
		panic(err)
	}
	packet.updateTimestamp()        //随时更新timestamp
	ipMeta.FinishProcessing(packet) //标记处理结束

	//由于tcp连接请求可能会超时 因此放入timeoutQueue
	//在到达超时时间点后会检查是否需要处理
	timeoutQueue <- packet
}
