#!/usr/bin/env python3
# 需root权限运行：sudo dart_ping.py example.com

import os
import sys
import time
import signal
import socket
import struct
import argparse
import socket
from random import randint
from datetime import datetime

# ================= 协议定义 =================
DART_PROTOCOL = 254  # IP协议号148标识DART协议
ICMP_PROTOCOL = 1   # DART内封装的ICMP协议


class DARTHeader:
    """DART协议头构造器"""
    def __init__(self, dst_fqdn, src_fqdn, upper_protocol):
        self.version = 1  # DART版本号，固定为1
        self.upper_protocol = upper_protocol  # 上层协议号（ICMP/TCP/UDP等）
        self.dst_len = len(dst_fqdn)  # 目标地址长度
        self.src_len = len(src_fqdn)  # 源地址长度
        self.dst = dst_fqdn.encode()  # 目标FQDN
        self.src = src_fqdn.encode()  # 源FQDN

    def pack(self):
        """将头部打包为二进制"""
        return struct.pack('!BBBB', 
                           self.version, 
                           self.upper_protocol, 
                           self.dst_len, 
                           self.src_len) + \
                self.dst + \
                self.src

class ICMPPacket:
    """ICMP数据包构造器"""
    def __init__(self, seq, payload_size=32):
        self.type = 8            # ICMP Echo Request
        self.code = 0            # 固定值
        self.checksum = 0        # 校验和
        self.id = os.getpid() & 0xFFFF  # 进程ID
        self.seq = seq           # 序列号
        self.payload = self._build_payload(payload_size)
        
    def _build_payload(self, size):
        """生成含时间戳的payload"""
        timestamp = struct.pack('!d', time.time())
        padding = bytes(randint(0,255) for _ in range(size - len(timestamp)))
        return timestamp + padding

    def calculate_checksum(self, data):
        """RFC1071校验和算法"""
        sum = 0
        for i in range(0, len(data), 2):
            if i < len(data) -1:
                sum += (data[i] << 8) + data[i+1] 
            else:
                sum += data[i] << 8
        sum = (sum >> 16) + (sum & 0xffff)
        sum += sum >> 16
        checksum = ~sum & 0xffff
        
        return ((checksum & 0xff) << 8) | ((checksum >> 8) & 0xff)

    
    
    def pack(self):
        """打包ICMP数据包"""
        header = struct.pack('!BBHHH', 
            self.type, self.code, self.checksum, self.id, self.seq)
        packet = header + self.payload
        self.checksum = self.calculate_checksum(packet)
        return struct.pack('!BBHHH', 
            self.type, self.code, 
            socket.htons(self.checksum), self.id, self.seq) + self.payload

# ================= 核心逻辑 =================
class DARTPinger:
    def __init__(self, target_fqdn, src_fqdn, ttl=64, timeout=2):
        self.target_fqdn = target_fqdn
        self.src_fqdn = src_fqdn
        self.ttl = ttl
        self.timeout = timeout
        self.send_sock = self._create_raw_socket_for_send()
        self.recv_sock = self._create_raw_socket_for_recv()
        
        # 统计信息
        self.sent_count = 0
        self.recv_count = 0
        self.rtt_list = []

    def _create_raw_socket_for_send(self):
        """创建原始套接字"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
        return sock

    def _create_raw_socket_for_recv(self):
        # 创建原始套接字并绑定所有接口
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, DART_PROTOCOL)
        sock.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)  # 包含IP头
        sock.bind(('0.0.0.0', 0))  # 监听所有接口
        return sock


    def _build_ip_header(self, total_len):
        """构造IP头部(proto=13)"""
        version_ihl = (4 << 4) | 5  # IPv4 + 5 * 4=20字节头部
        return struct.pack('!BBHHHBBH4s4s',
            version_ihl, 0,         # 版本/IHL, DSCP/ECN
            total_len,              # 总长度
            randint(0, 0xFFFF),     # 标识
            0,                      # 分片偏移
            64,                     # TTL
            DART_PROTOCOL,          # 协议号
            0,                      # 校验和(自动计算)
            socket.inet_aton('0.0.0.0'), # 源IP(系统自动填充)
            socket.inet_aton(socket.gethostbyname(self.target_fqdn))) # 目标IP

    def send_packet(self, seq):
        """发送DART+ICMP数据包"""
        # 构造协议头
        dart_header = DARTHeader(self.target_fqdn, self.src_fqdn, ICMP_PROTOCOL)
        icmp_packet = ICMPPacket(seq).pack()

        # 组装完整数据包
        data = dart_header.pack() + icmp_packet
        ip_header = self._build_ip_header(len(data) + 20)

        # 发送数据
        self.send_sock.sendto(ip_header + data, (self.target_fqdn, 0))
        self.sent_count += 1
        return time.time()

    def recv_response(self):
        """接收响应包"""
        self.recv_sock.settimeout(self.timeout)  # 设置超时时间
        try:
            pkt, addr = self.recv_sock.recvfrom(4096)
            recv_time = time.time()

            # 解析IP头部
            ip_header = pkt[:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            # 验证DART协议
            if iph[6] != DART_PROTOCOL:
                return None, None, None, None, None

            # 解析DART头部
            dart_start = 20
            version, upper_protocol = struct.unpack('!BB', pkt[dart_start:dart_start+2])
            if version != 1 or upper_protocol != ICMP_PROTOCOL:
                return None, None, None, None, None

            dst_len  = pkt[dart_start + 2]  # 目标地址长度
            src_len  = pkt[dart_start + 3]  # 源地址长度
            dst_fqdn = pkt[dart_start + 4 : dart_start+4+dst_len].decode()  # 目标地址
            src_fqdn = pkt[dart_start + 4 + dst_len : dart_start+4+dst_len+src_len].decode()  # 源地址

            # 解析ICMP响应
            icmp_start = dart_start + 4 + dst_len + src_len
            icmph = struct.unpack('!BBHHH', pkt[icmp_start:icmp_start+8])
            if icmph[0] == 0 and icmph[1] == 0:  # ICMP Echo Reply
                sent_time = struct.unpack('!d', pkt[icmp_start+8:icmp_start+16])[0]
                rtt = (recv_time - sent_time) * 1000
                self.rtt_list.append(rtt)
                self.recv_count += 1
                seq = icmph[4]  # seq在ICMP头部的第5个字节
                return seq, rtt, addr[0], src_fqdn, pkt

        except socket.timeout:
            # 超时返回 None
            return None, None, None, None, None

# ================= 主程序 =================
def signal_handler(sig, frame):
    """Ctrl-C信号处理"""
    print(f"\n--- {pinger.target_fqdn} ping statistics ---")
    loss = 100 * (pinger.sent_count - pinger.recv_count) / pinger.sent_count
    print(f"{pinger.sent_count} packets transmitted, {pinger.recv_count} received, "
          f"{loss:.1f}% packet loss")
    if pinger.rtt_list:
        print(f"rtt min/avg/max = {min(filter(None, pinger.rtt_list)):.2f}/"
              f"{sum(filter(None, pinger.rtt_list))/len(filter(None, pinger.rtt_list)):.2f}/"
              f"{max(filter(None, pinger.rtt_list)):.2f} ms")
    sys.exit(0)

import subprocess

def get_dhcp_domain_name():
    # 方法 1: 使用 resolvectl
    try:
        output = subprocess.check_output(["resolvectl", "status"], encoding="utf-8")
        for line in output.splitlines():
            if "DNS Domain" in line:
                domain = line.split(":", 1)[1].strip()
                if domain:
                    return domain
    except Exception as e:
        print("resolvectl error:", e)

    # 方法 2: fallback 到 /etc/resolv.conf
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("search") or line.startswith("domain"):
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        return parts[1]
    except Exception as e:
        print("resolv.conf error:", e)

    return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='DART Protocol Ping')
    parser.add_argument('target', help='Target FQDN address')
    parser.add_argument('-i', '--interval', type=float, default=1, help='Interval between packets')
    parser.add_argument('-t', '--timeout', type=float, default=2, help='等待响应的超时时间（秒）')  # 新增此行
    parser.add_argument('--ttl', type=int, default=64, help='Time To Live')
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    
    # 获取本地FQDN
    domain = get_dhcp_domain_name()
    hostname = socket.gethostname()
    src_fqdn = f"{hostname}.{domain}" if domain else hostname

    pinger = DARTPinger(args.target, src_fqdn, ttl=args.ttl)
    
    print(f"PING {args.target} ({socket.gethostbyname(args.target)}) via DART protocol")
    seq = 0
    
    while True:
        send_time = pinger.send_packet(seq)
        start_time = time.time()
        timeout_occurred = True  # 默认认为超时

        while True:
            elapsed = time.time() - start_time
            if elapsed > args.timeout:
                print(f"Request timeout for icmp_seq {seq}")
                break

            recv_seq, rtt, addr, dst_fqdn, pkt = pinger.recv_response()
            if recv_seq == seq:
                print(f"{len(pkt)} bytes from {dst_fqdn} ({addr}): "
                      f"icmp_seq={seq} ttl={args.ttl} time={rtt:.2f} ms")
                timeout_occurred = False  # 收到响应，取消超时标记
                break

        if timeout_occurred:
            # 超时丢包计数
            pinger.rtt_list.append(None)

        seq += 1
        time.sleep(args.interval)