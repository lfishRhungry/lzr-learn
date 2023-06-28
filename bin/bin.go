package bin

import (
	"time"
	//"context"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"sync"

	"github.com/stanford-esrg/lzr"
)

func LZRMain() {

	start := time.Now()

	//解析配置文件
	options, ok := lzr.Parse()
	if !ok {
		fmt.Fprintln(os.Stderr, "Failed to parse command line options, exiting.")
		return
	}

	//For CPUProfiling
	if options.CPUProfile != "" {
		f, err := os.Create(options.CPUProfile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	//!-----------------------------------------------------------------------各种Routine和Queue的初始化
	ipMeta := lzr.ConstructPacketStateMap(options) //构造维护packet状态的map
	f := lzr.InitFile(options.Filename)            //用于结果输出的Writer
	lzr.InitParams()                               //获取网关mac和本机mac

	//创建Routine需要用到的各种Queue通道
	writingQueue := lzr.ConstructWritingQueue()       //用于放入处理完毕后需要记录结果的packet_metadata
	timeoutQueue := lzr.ConstructTimeoutQueue()       //用于放入lzr刚发出tcp连接请求后的packet_metadata
	retransmitQueue := lzr.ConstructRetransmitQueue() //用于放入可能需要重传的packet_metadata

	//创建各Routine并得到其incoming通道
	pcapIncoming := lzr.ConstructPcapRoutine(options.Workers)                                                                 //可取出pcap获取的除syn包外的packet_metadata
	timeoutIncoming := lzr.PollTimeoutRoutine(&ipMeta, timeoutQueue, retransmitQueue, options.Timeout, options.RetransmitSec) //可取出因tcp请求超时或已到达重传时间但没被确认的状态下的packet_metadata
	incoming := lzr.ConstructIncomingRoutine()                                                                                //可取出从stdin或zmap读取的packet_metadata

	isWriting := false
	// 该goroutine从writingQueue中取出需要记录的packet_metadata并记录到结果
	go func() {
		for input := range writingQueue {
			isWriting = true
			f.Record(input, options.Handshakes)
			isWriting = false
		}
	}()
	//!-----------------------------------以上初始化工作完成后 由于负责incoming类型通道的Routine已经给创建并开始工作 特别是pcapIncoming和incoming通道已经开始在被feed

	//!-----------------------------------然后根据workers数量 启动各项工作 本质是在已有Routine基础上 填补各类Queue、incoming之间周转packet_metadata的逻辑

	var incomingDone sync.WaitGroup   //指示各个处理从incoming取出的包的worker goroutine都结束工作
	incomingDone.Add(options.Workers) //由用户指定worker goroutine数量
	ipMetaIsDone := false             //指示维护的状态已经处理完毕（或者进入死循环 不必继续处理）

	//!处理incoming中获取的packet_metadata（来自stdin或zmap）
	//使用workers数量goroutine
	for i := 0; i < options.Workers; i++ {
		go func(i int) {
			for inputPacket := range incoming {
				if lzr.ReadZMap() {
					toACK := true   //zmap接续情况下 对incoming中的包需要回复ack
					toPUSH := false //第一次响应ack 不需要push
					lzr.SendAck(options, inputPacket, &ipMeta, retransmitQueue, writingQueue, toACK, toPUSH, lzr.ACK)
				} else {
					//lzr主动启动探测的情况下 根据构造的“假回包”发送syn包
					lzr.SendSyn(inputPacket, &ipMeta, timeoutQueue)
				}
				ipMeta.FinishProcessing(inputPacket) //标记处理结束
			}

			//运行到此 说明incoming通道中不再有新的包
			//!接下来还需要等待维护状态中的剩余事务处理完毕
			//因为后文的显示退出条件是incomingDone
			//所以这里要对ipMeta进行善后才执行incomingDone.Done()

			//挨个对worker进行处理
			if i == options.Workers-1 {
				//注意，这里不能干等ipMeta 由于一些不确定复杂因素 ipMeta维护的状态在被处理时可能进入无限循环
				//因此 这里给一个判定条件：如果ipMeta维护的状态数量 经过numHandshakes*timeout*2的时间后还是相同的
				var isInfiniteLoop = false
				var ipMetaSize = ipMeta.Count()
				var intervalLoop = options.Timeout * lzr.NumHandshakes() * 2

				//单独开启一个goroutine的原因：由于每个worker都有该检查逻辑 只要一个worker先确定ipMetaIsDone=true
				//在存在infiniteloop的情况下，后续worker就不必再利用等候时间来重复确认
				go func() {
					for {
						time.Sleep(time.Duration(intervalLoop) * time.Second)
						if ipMetaSize == ipMeta.Count() {
							fmt.Fprintln(os.Stderr, "Infinite Loop, Breaking.")
							isInfiniteLoop = true
							return
						} else {
							ipMetaSize = ipMeta.Count()
						}
					}
				}()
				for {
					if ipMeta.IsEmpty() || isInfiniteLoop {
						ipMetaIsDone = true
						break
					}
					//slow down to prevent CPU busy looping
					time.Sleep(1 * time.Second)
					fmt.Fprintln(os.Stderr, "Finishing Last:", ipMeta.Count())
				}
			}
			//善后ipMeta中的剩余状态后 可以指示本worker工作完毕
			incomingDone.Done()
		}(i)
	}

	//!处理从pcap中获取的packet_metadata
	//使用workers数量goroutine
	for i := 0; i < options.Workers; i++ {
		go func(i int) {
			for inputPacket := range pcapIncoming {
				//已经存在状态 且没有正在处理的情况下 才可以开始处理
				//注意 这里检查的不是inputPacket 而是其所属状态
				inMap, canStartProcessing := ipMeta.IsStartProcessing(inputPacket)
				//过滤掉没有为其维护状态的包
				if !inMap {
					continue
				}
				//如果有其他goroutine在处理该连接事务（该包可能是来自目标主机的重传）, 先放回pcapIncoming 一会再弄
				if !canStartProcessing {
					pcapIncoming <- inputPacket
					continue
				}
				lzr.HandlePcap(options, inputPacket, &ipMeta, timeoutQueue,
					retransmitQueue, writingQueue)
				//标记处理完毕
				ipMeta.FinishProcessing(inputPacket)
			}
		}(i)
	}

	//!处理timeoutIncoming中到达超时时间且需要处理的包（连接请求超时 或 到达重传时间且状态还未更新）
	go func() {

		for inputPacket := range timeoutIncoming {
			//已经存在状态 且没有正在处理的情况下 才可以开始处理
			//注意 这里检查的不是inputPacket 而是其所属状态
			inMap, startProcessing := ipMeta.IsStartProcessing(inputPacket)
			//过滤掉没有为其维护状态的包
			if !inMap {
				continue
			}
			//如果有其他goroutine在处理该连接事务（该包可能是来自目标主机的重传）, 先放回pcapIncoming 一会再弄
			if !startProcessing {
				timeoutIncoming <- inputPacket
				continue
			}

			lzr.HandleTimeout(options, inputPacket, &ipMeta, timeoutQueue, retransmitQueue, writingQueue)
			ipMeta.FinishProcessing(inputPacket)
		}
	}()

	//程序退出重要条件
	incomingDone.Wait()

	for {
		if ipMetaIsDone && len(writingQueue) == 0 && !isWriting {
			if options.MemProfile != "" {
				f, err := os.Create(options.MemProfile)
				if err != nil {
					log.Fatal(err)
				}
				pprof.WriteHeapProfile(f)
				f.Close()
			}
			//closing file
			f.F.Flush()
			t := time.Now()
			elapsed := t.Sub(start)
			lzr.Summarize(elapsed)
			return
		}
	}

}
