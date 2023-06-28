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
//该文件保存用于lzr构造其响应包的功能函数（即向外发包）
package lzr

import (
	"bytes"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	//"fmt"
)

// 获取该回包的源mac
func saveHostMacAddr(packet *packet_metadata) {
	dest_mac = packet.getSourceMac()
}

// 获取本地主机mac
func getSourceMacAddr() (addr string) {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, i := range interfaces {
			if i.Flags&net.FlagUp != 0 && !bytes.Equal(i.HardwareAddr, nil) {
				if i.Name != getDevice() {
					continue
				}
				addr = i.HardwareAddr.String()
			}
		}
	}
	return addr
}

// 构造链路层数据
func constructEthLayer() (eth *layers.Ethernet) {

	smac, _ := net.ParseMAC(source_mac)
	dmac, _ := net.ParseMAC(dest_mac)

	ethernetLayer := &layers.Ethernet{
		SrcMAC: smac,
		DstMAC: dmac,
		//EthernetType: layers.EthernetTypeARP,
		EthernetType: layers.EthernetTypeIPv4,
	}

	return ethernetLayer

}

/* 根据“假回包”，构造用于lzr响应的syn包（即发出去的syn包）
 * 因此Dest/Src要交换
 * 其实该回包是虚拟的（syn包都还没发出去，哪里来的回包）
 * 但是为了符合根据WritingQueue中的已有包构造lzr的响应包的工作流程
 * 管道的另一头使用如下函数，根据输入的IP:port自行构造假回包，放入WritingQueue
 * func convertFromInputListToPacket(input string) *packet_metadata
 * 从WritingQueue中取出来后 这里真正构造第一个syn包
 */
func constructSYN(p *packet_metadata) []byte {

	ethernetLayer := constructEthLayer()

	//从回包构造发包 需要置反
	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP(p.Daddr),
		DstIP:    net.ParseIP(p.Saddr),
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
	}

	//注意，这里根据“假回包”构造syn包时
	//Seq Ack Window都是直接复制
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(p.Dport),
		DstPort: layers.TCPPort(p.Sport),
		Seq:     uint32(p.Seqnum),
		Ack:     uint32(p.Acknum),
		Window:  uint16(p.Window), //65535,
		SYN:     true,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// And create the packet with the layers
	if err := gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
	); err != nil {
		log.Fatal(err)

	}
	outPacket := buffer.Bytes()
	return outPacket
}

// 根据提供的syn-ack回包和handshake类型，返回用来响应的原始ack包（含数据）和相应的数据内容
func constructData(handshake Handshake, p *packet_metadata, ack bool, push bool) ([]byte, []byte) {

	//data := []byte("\n")

	data := handshake.GetData(string(p.Saddr))
	if PushDOnly() && !push {
		data = []byte("")
	}
	ethernetLayer := constructEthLayer()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP(p.Daddr),
		DstIP:    net.ParseIP(p.Saddr),
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(p.Dport),
		DstPort: layers.TCPPort(p.Sport),
		Seq:     uint32(p.Acknum),
		Ack:     uint32(p.Seqnum + 1),
		Window:  uint16(p.Window),
		ACK:     ack,
		PSH:     push,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	// And create the packet with the layers
	if err := gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(data),
	); err != nil {
		log.Fatal(err)
	}

	outPacket := buffer.Bytes()
	return outPacket, data

}

/* 根据提供的回包构建原始RST响应包
 * Daddr/Saddr需要置反
 */
func constructRST(ack *packet_metadata) []byte {

	ethernetLayer := constructEthLayer()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP(ack.Daddr),
		DstIP:    net.ParseIP(ack.Saddr),
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		Version:  4,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(ack.Dport),
		DstPort: layers.TCPPort(ack.Sport),
		Seq:     uint32(ack.Acknum), //NOT SURE
		Ack:     0,
		Window:  0,
		RST:     true,
	}

	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	// And create the packet with the layers
	if err := gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
	); err != nil {
		log.Fatal(err)

	}
	outPacket := buffer.Bytes()
	return outPacket

}
