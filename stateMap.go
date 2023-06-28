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
	"fmt"
	"strconv"
)

/* 构建一系列map用来维持数据包状态
 *状态中会保存该连接中上一次收到的包，并在包中保存希望得到的下一次响应类型
 * map中实际存储元素为*packet_state
 */
func ConstructPacketStateMap(opts *options) pState {
	ipMeta := NewpState()
	return ipMeta
}

// 获取该packet_metadata在map中的key值
// 由此可知 对于和同一Saddr和Sport的交互状态
// 同一时刻在StateMap中只会保存一个包
// 且该包属于回包 因此Saddr和Sport指的是目标的属性
func constructKey(packet *packet_metadata) string {
	return packet.Saddr + ":" + strconv.Itoa(packet.Sport)
}

func constructParentKey(packet *packet_metadata, parentSport int) string {
	return packet.Saddr + ":" + strconv.Itoa(parentSport)
}

// 当前维护的状态中是否包含该packet_metadata
func (ipMeta *pState) metaContains(p *packet_metadata) bool {

	pKey := constructKey(p)
	return ipMeta.Has(pKey)

}

// 从当前维护的状态中查找该packet_metadata
func (ipMeta *pState) find(p *packet_metadata) (*packet_metadata, bool) {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		return ps.Packet, ok
	}
	return nil, ok
}

// 使用新收到的packet数据更新该packet所属连接的状态
// 如果没有状态则创建
func (ipMeta *pState) update(p *packet_metadata) {

	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	//没有状态就创建一个新状态
	if !ok {
		ps = &packet_state{
			Packet:       p,
			Ack:          false,
			HandshakeNum: 0,
		}
	} else {
		ps.Packet = p
	}
	ipMeta.Insert(pKey, ps)
}

// 将包所属状态的handshake类型序号增1
func (ipMeta *pState) incHandshake(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		ps.HandshakeNum += 1
		ipMeta.Insert(pKey, ps)
	}
	return ok
}

// 标记该状态已到达accept data阶段
func (ipMeta *pState) updateAck(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		ps.Ack = true
		ipMeta.Insert(pKey, ps)
	}
	return ok
}

func (ipMeta *pState) getAck(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		return ps.Ack
	}
	return false
}

// 将短暂端口响应次数增1
func (ipMeta *pState) incEphemeralResp(p *packet_metadata, sport int) bool {
	pKey := constructParentKey(p, sport)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		ps.EphemeralRespNum += 1
		ipMeta.Insert(pKey, ps)
	}
	return ok
}

func (ipMeta *pState) getEphemeralRespNum(p *packet_metadata) int {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		return ps.EphemeralRespNum
	}
	return 0
}

func (ipMeta *pState) getHyperACKtiveStatus(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		return ps.HyperACKtive
	}
	return false
}

// 将该包所属状态标记为“用来探测全响应的连接”
func (ipMeta *pState) setHyperACKtiveStatus(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		ps.HyperACKtive = true
		ipMeta.Insert(pKey, ps)
	}
	return ok
}

// p用来探测全响应 因为为其所属状态设置父端口sport
func (ipMeta *pState) setParentSport(p *packet_metadata, sport int) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		ps.ParentSport = sport
		ipMeta.Insert(pKey, ps)
	}
	return ok
}

func (ipMeta *pState) getParentSport(p *packet_metadata) int {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		return ps.ParentSport
	}
	return 0
}

func (ipMeta *pState) recordEphemeral(p *packet_metadata, ephemerals []packet_metadata) bool {

	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		ps.EphemeralFilters = append(ps.EphemeralFilters, ephemerals...)
		ipMeta.Insert(pKey, ps)
	}
	return ok

}

func (ipMeta *pState) getEphemeralFilters(p *packet_metadata) ([]packet_metadata, bool) {

	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		return ps.EphemeralFilters, ok
	}
	return nil, ok

}

// 标记该连接已经收到了目标的数据
func (ipMeta *pState) updateData(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		ps.Data = true
		ipMeta.Insert(pKey, ps)
	}
	return ok
}

// 检查该连接是否已经收到了目标的数据
func (ipMeta *pState) getData(p *packet_metadata) bool {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		return ps.Data
	}
	return false
}

// 获取p包在状态维护中记录的正在进行的handshake类型序号
func (ipMeta *pState) getHandshake(p *packet_metadata) int {
	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if ok {
		return ps.HandshakeNum
	}
	return 0
}

func (ipMeta *pState) incrementCounter(p *packet_metadata) bool {

	pKey := constructKey(p)
	ps, ok := ipMeta.Get(pKey)
	if !ok {
		return false
	}
	ps.Packet.incrementCounter()
	ipMeta.Insert(pKey, ps)
	return true

}

// 将该维护状态删除
func (ipMeta *pState) remove(packet *packet_metadata) *packet_metadata {
	packet.ACKed = ipMeta.getAck(packet)
	packetKey := constructKey(packet)
	ipMeta.Remove(packetKey)
	return packet
}

// 在verifyScanningIP函数确认过4元组的前提下
// 进一步检测pRecv是否是针对pMap所属状态连接的回复
// 主要是标志位和各种序号
func verifySA(pMap *packet_metadata, pRecv *packet_metadata) bool {

	//是否是syn-ack响应
	if pRecv.SYN && pRecv.ACK {
		//如果是syn-ack 则pMap是之前构造的“假回包”
		//“假回包”的ack seq window值与发出的syn包相同
		//因此acknum是这么检查的
		if pRecv.Acknum == pMap.Seqnum+1 {
			return true
		}
	} else {
		//如果不是syn-ack，则seq要正确
		if (pRecv.Seqnum == (pMap.Seqnum)) || (pRecv.Seqnum == (pMap.Seqnum + 1)) {
			//普通的确认数据
			if pRecv.Acknum == (pMap.Acknum + pMap.LZRResponseL) {
				return true
			}
			//RST
			if pRecv.Acknum == 0 { //for RSTs
				return true
			}
		}
	}
	return false

}

// 确认该pRecv包是否是一个已维护状态连接的回包（无论是syn syn-ack RST）
func (ipMeta *pState) verifyScanningIP(pRecv *packet_metadata) bool {

	pRecvKey := constructKey(pRecv)
	//首先，在维护的状态map中查找
	ps, ok := ipMeta.Get(pRecvKey)
	if !ok {
		return false
	}
	pMap := ps.Packet //取出状态维护中的最后一次回包

	//检查4元组是否匹配 这里相比刚才的检查 多了一项对回包的Dport核查
	if (pMap.Saddr == pRecv.Saddr) && (pMap.Dport == pRecv.Dport) &&
		(pMap.Sport == pRecv.Sport) {
		//4元组匹配的情况下，再检查字段中flag和序号的正确性
		if verifySA(pMap, pRecv) {
			return true
		}
	}

	/*//lets re-query for the ACKtive packets
	pRecv.HyperACKtive = true
	pRecvKey = constructKey(pRecv)
	ps, ok = ipMeta.Get( pRecvKey )
	if !ok {
		pRecv.HyperACKtive = false
		return false
	}
	pMap = ps.Packet

	if verifySA( pMap, pRecv) {
		return true
	}
	pRecv.HyperACKtive = false
	*/
	if DebugOn() {
		fmt.Println(pMap.Saddr, "====")
		fmt.Println("recv seq num:", pRecv.Seqnum)
		fmt.Println("stored seqnum: ", pMap.Seqnum)
		fmt.Println("recv ack num:", pRecv.Acknum)
		fmt.Println("stored acknum: ", pMap.Acknum)
		fmt.Println("received response length: ", len(pRecv.Data))
		fmt.Println("stored response length: ", pMap.LZRResponseL)
		fmt.Println(pMap.Saddr, "====")
	}
	return false

}
