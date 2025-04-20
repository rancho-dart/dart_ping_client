package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	DART_PROTOCOL = 254
	ICMP_PROTOCOL = 1
	ICMP_ECHO     = 8
	ICMP_REPLY    = 0
)

type DARTHeader struct {
	Version       uint8
	UpperProtocol uint8
	DstLen        uint8
	SrcLen        uint8
	DstFQDN       []byte
	SrcFQDN       []byte
}

type ICMPPacket struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Payload  []byte
}

type DARTPinger struct {
	TargetFQDN string
	SrcFQDN    string
	TTL        int
	Timeout    time.Duration
	SentCount  int
	RecvCount  int
	RTTs       []time.Duration
	PacketSize int
	Count      int
	Flood      bool
}

func (h *DARTHeader) Pack() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h.Version)
	binary.Write(buf, binary.BigEndian, h.UpperProtocol)
	binary.Write(buf, binary.BigEndian, h.DstLen)
	binary.Write(buf, binary.BigEndian, h.SrcLen)
	buf.Write(h.DstFQDN)
	buf.Write(h.SrcFQDN)
	return buf.Bytes()
}

func (h *DARTHeader) size() int {
	return 4 + len(h.DstFQDN) + len(h.SrcFQDN)
}

func (p *ICMPPacket) CalculateChecksum() uint16 {
	p.Checksum = 0
	var sum uint32

	data := p.Pack()
	for i := 0; i < len(data); i += 2 {
		if i+1 < len(data) {
			sum += uint32(data[i])<<8 | uint32(data[i+1]) // 修正高低字节顺序
		} else {
			sum += uint32(data[i])
		}
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(^sum)
}

func (p *ICMPPacket) Pack() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, p.Type)
	binary.Write(buf, binary.BigEndian, p.Code)
	binary.Write(buf, binary.BigEndian, p.Checksum)
	binary.Write(buf, binary.BigEndian, p.ID)
	binary.Write(buf, binary.BigEndian, p.Seq)
	buf.Write(p.Payload)
	return buf.Bytes()
}

func NewICMPPacket(seq uint16, payloadSize int) *ICMPPacket {
	p := &ICMPPacket{
		Type:    ICMP_ECHO,
		Code:    0,
		ID:      uint16(os.Getpid() & 0xffff),
		Seq:     seq,
		Payload: make([]byte, payloadSize),
	}

	// 填充时间戳和随机数据
	binary.BigEndian.PutUint64(p.Payload[:8], uint64(time.Now().UnixNano()))
	for i := 8; i < len(p.Payload); i++ {
		p.Payload[i] = byte(rand.Intn(256))
	}

	p.Checksum = p.CalculateChecksum()
	return p
}

func (p *DARTPinger) SendPacket(seq uint16) (time.Time, error) {
	dartHeader := &DARTHeader{
		Version:       1,
		UpperProtocol: ICMP_PROTOCOL,
		DstLen:        uint8(len(p.TargetFQDN)),
		SrcLen:        uint8(len(p.SrcFQDN)),
		DstFQDN:       []byte(p.TargetFQDN),
		SrcFQDN:       []byte(p.SrcFQDN),
	}

	icmpPacket := NewICMPPacket(seq, p.PacketSize-dartHeader.size()-8) // ICMP报头8字节 + DART报头大小
	packet := append(dartHeader.Pack(), icmpPacket.Pack()...)

	conn, err := net.Dial(fmt.Sprintf("ip4:%d", DART_PROTOCOL), p.TargetFQDN) //
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()

	rawConn, err := conn.(*net.IPConn).SyscallConn() // 获取原始连接
	if err != nil {
		return time.Time{}, err
	}

	rawConn.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, p.TTL)
	})

	start := time.Now()
	_, err = conn.Write(packet)
	if err != nil {
		return time.Time{}, err
	}

	p.SentCount++
	return start, nil
}

func (p *DARTPinger) RecvResponse(seq uint16, start time.Time) (bool, time.Duration, int, error) {
	conn, err := net.ListenPacket(fmt.Sprintf("ip4:%d", DART_PROTOCOL), "0.0.0.0")
	if err != nil {
		return false, 0, 0, err
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(p.Timeout))
	if err != nil {
		return false, 0, 0, err
	}

	recvBuf := make([]byte, 4096)
	for {
		pktSize, _, err := conn.ReadFrom(recvBuf) // pktSize只包含从DART报头开始的字节数
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				return false, 0, 0, nil // Timeout
			}
			return false, 0, 0, err
		}

		dartStart := 0
		if recvBuf[dartStart] != 1 || recvBuf[dartStart+1] != ICMP_PROTOCOL {
			continue // 版本或协议不匹配
		}

		// 解析ICMP响应
		icmpStart := int(dartStart) + 4 + int(recvBuf[dartStart+2]) + int(recvBuf[dartStart+3])
		if pktSize < icmpStart+8 {
			continue
		}

		if recvBuf[icmpStart] == ICMP_REPLY && recvBuf[icmpStart+1] == 0 {
			recvSeq := binary.BigEndian.Uint16(recvBuf[icmpStart+6 : icmpStart+8])
			if recvSeq == seq {
				sentTime := time.Unix(0, int64(binary.BigEndian.Uint64(recvBuf[icmpStart+8:icmpStart+16])))
				rtt := time.Since(sentTime)
				p.RTTs = append(p.RTTs, rtt)
				p.RecvCount++
				return true, rtt, pktSize, nil
			}
		}
	}
}

func getFQDN() string {
	var domain string

	// 方法 1: 使用 resolvectl 获取域名
	cmd := exec.Command("resolvectl", "status")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "DNS Domain") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					domain = strings.TrimSpace(parts[1])
					break
				}
			}
		}
	}

	// 方法 2: fallback 到 /etc/resolv.conf
	if domain == "" {
		file, err := os.Open("/etc/resolv.conf")
		if err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "search") || strings.HasPrefix(line, "domain") {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						domain = parts[1]
						break
					}
				}
			}
		}
	}

	// 获取主机名
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}

	// 拼接 FQDN
	if domain != "" {
		return fmt.Sprintf("%s.%s", hostname, domain)
	}
	return hostname
}

func main() {
	var packetSize int
	var count int
	var flood bool

	flag.IntVar(&packetSize, "s", 64, "Specify the packet size")
	flag.IntVar(&count, "c", -1, "Specify the number of packets to send")
	flag.BoolVar(&flood, "f", false, "Enable flood ping mode")
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Println("Usage: sudo ./dart_ping [-s packet_size] [-c count] [-f] <target>")
		os.Exit(1)
	}

	target := flag.Args()[0]
	srcFQDN := getFQDN()

	pinger := &DARTPinger{
		TargetFQDN: target,
		SrcFQDN:    srcFQDN,
		TTL:        64,
		Timeout:    2 * time.Second,
		PacketSize: packetSize,
		Count:      count,
		Flood:      flood,
	}

	// 处理Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT)
	go func() {
		<-sigCh
		pinger.PrintStats()
		os.Exit(0)
	}()

	ipAddr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("PING %s (%s - if not in same domain, this ip is actually the gateway :-)) via DART protocol\n", target, ipAddr)

	seq := uint16(0)
	for {
		if pinger.Count > 0 && pinger.SentCount >= pinger.Count {
			break
		}

		start, err := pinger.SendPacket(seq)
		if err != nil {
			log.Printf("Send error: %v", err)
			continue
		}

		success, rtt, n, err := pinger.RecvResponse(seq, start)
		if err != nil {
			log.Printf("Receive error: %v", err)
		}

		if success {
			fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.2f ms\n",
				n, pinger.TargetFQDN, seq, pinger.TTL, float64(rtt.Microseconds())/1000)
		} else {
			fmt.Printf("Request timeout for icmp_seq %d\n", seq)
		}

		seq++
		if !pinger.Flood {
			time.Sleep(1 * time.Second)
		}
	}

	pinger.PrintStats()
}

func (p *DARTPinger) PrintStats() {
	fmt.Printf("\n--- %s ping statistics ---\n", p.TargetFQDN)
	loss := float64(p.SentCount-p.RecvCount) / float64(p.SentCount) * 100
	fmt.Printf("%d packets transmitted, %d received, %.1f%% packet loss\n",
		p.SentCount, p.RecvCount, loss)

	if len(p.RTTs) > 0 {
		var min, max, sum time.Duration
		min, max = p.RTTs[0], p.RTTs[0]
		for _, rtt := range p.RTTs {
			if rtt < min {
				min = rtt
			}
			if rtt > max {
				max = rtt
			}
			sum += rtt
		}
		avg := sum / time.Duration(len(p.RTTs))
		fmt.Printf("rtt min/avg/max = %.2f/%.2f/%.2f ms\n",
			float64(min.Microseconds())/1000,
			float64(avg.Microseconds())/1000,
			float64(max.Microseconds())/1000)
	}
}
