import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

// Constants
const DART_PROTOCOL = 254; // IP protocol number for DART
const ICMP_PROTOCOL = 1;   // ICMP protocol number
const ICMP_ECHO_REQUEST = 8;
const ICMP_ECHO_REPLY = 0;

class DARTHeader {
  int version = 1;
  int upperProtocol;
  int dstLen;
  int srcLen;
  Uint8List dst;
  Uint8List src;

  DARTHeader(String dstFqdn, String srcFqdn, this.upperProtocol)
      : dst = Uint8List.fromList(dstFqdn.codeUnits),
        src = Uint8List.fromList(srcFqdn.codeUnits),
        dstLen = dstFqdn.length,
        srcLen = srcFqdn.length;

  Uint8List pack() {
    var header = ByteData(4);
    header.setUint8(0, version);
    header.setUint8(1, upperProtocol);
    header.setUint8(2, dstLen);
    header.setUint8(3, srcLen);
    
    var result = Uint8List(4 + dstLen + srcLen);
    result.setAll(0, header.buffer.asUint8List().sublist(0, 4));
    result.setAll(4, dst);
    result.setAll(4 + dstLen, src);
    
    return result;
  }
}

class ICMPPacket {
  int type = ICMP_ECHO_REQUEST;
  int code = 0;
  int checksum = 0;
  int id;
  int seq;
  Uint8List payload;
  
  ICMPPacket(this.seq, {int payloadSize = 32}) : id = pid() & 0xFFFF {
    payload = _buildPayload(payloadSize);
  }
  
  Uint8List _buildPayload(int size) {
    var timestamp = ByteData(8);
    timestamp.setFloat64(0, DateTime.now().millisecondsSinceEpoch / 1000, Endian.big);
    var padding = List<int>.generate(size - 8, (_) => Random().nextInt(256));
    return Uint8List.fromList(timestamp.buffer.asUint8List() + padding);
  }
  
  int calculateChecksum(Uint8List data) {
    var sum = 0;
    for (var i = 0; i < data.length; i += 2) {
      if (i < data.length - 1) {
        sum += (data[i] << 8) + data[i + 1];
      } else {
        sum += data[i] << 8;
      }
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += sum >> 16;
    var checksum = ~sum & 0xffff;
    return ((checksum & 0xff) << 8) | ((checksum >> 8) & 0xff);
  }
  
  Uint8List pack() {
    var header = ByteData(8);
    header.setUint8(0, type);
    header.setUint8(1, code);
    header.setUint16(2, checksum, Endian.big);
    header.setUint16(4, id, Endian.big);
    header.setUint16(6, seq, Endian.big);
    
    var packet = Uint8List.fromList(header.buffer.asUint8List() + payload);
    checksum = calculateChecksum(packet);
    
    header.setUint16(2, checksum, Endian.big);
    return Uint8List.fromList(header.buffer.asUint8List() + payload);
  }
  
  int pid() {
    return Process.current.pid;
  }
}

class DARTPinger {
  final String targetFqdn;
  final String srcFqdn;
  final int ttl;
  final int timeout;
  
  RawSocket? sendSocket;
  RawSocket? recvSocket;
  
  int sentCount = 0;
  int recvCount = 0;
  List<double?> rttList = [];
  
  DARTPinger(this.targetFqdn, this.srcFqdn, {this.ttl = 64, this.timeout = 2});
  
  Future<void> initialize() async {
    sendSocket = await RawSocket.connect(targetFqdn, 0, timeout: Duration(seconds: timeout));
    recvSocket = await RawSocket.bind(InternetAddress.anyIPv4, 0);
    
    // Set socket options
    sendSocket?.setOption(SocketOption.ipTtl, ttl);
    sendSocket?.setOption(SocketOption.ipReceivePacketInfo, true);
  }
  
  Uint8List _buildIpHeader(int totalLen) {
    var header = ByteData(20);
    header.setUint8(0, (4 << 4) | 5); // Version and IHL
    header.setUint8(1, 0); // DSCP/ECN
    header.setUint16(2, totalLen, Endian.big); // Total length
    header.setUint16(4, Random().nextInt(0xFFFF), Endian.big); // Identification
    header.setUint16(6, 0, Endian.big); // Flags and fragment offset
    header.setUint8(8, ttl); // TTL
    header.setUint8(9, DART_PROTOCOL); // Protocol
    header.setUint16(10, 0, Endian.big); // Header checksum (0 for now)
    
    // Source and destination addresses (will be filled by system)
    header.setUint32(12, 0, Endian.big); // Source IP
    header.setUint32(16, InternetAddress(targetFqdn).rawAddress.buffer.asByteData().getUint32(0, Endian.big); // Destination IP
    
    return header.buffer.asUint8List();
  }
  
  Future<double> sendPacket(int seq) async {
    if (sendSocket == null) {
      await initialize();
    }
    
    var dartHeader = DARTHeader(targetFqdn, srcFqdn, ICMP_PROTOCOL).pack();
    var icmpPacket = ICMPPacket(seq).pack();
    var data = Uint8List.fromList(dartHeader + icmpPacket);
    var ipHeader = _buildIpHeader(data.length + 20);
    
    var fullPacket = Uint8List.fromList(ipHeader + data);
    sendSocket?.write(fullPacket);
    sentCount++;
    
    return DateTime.now().millisecondsSinceEpoch / 1000;
  }
  
  Future<({int? seq, double? rtt, String? addr, String? srcFqdn, Uint8List? packet})> 
      recvResponse() async {
    if (recvSocket == null) {
      await initialize();
    }
    
    try {
      var subscription = recvSocket!.asBroadcastStream().timeout(Duration(seconds: timeout));
      await for (var event in subscription) {
        if (event is RawSocketEvent.read) {
          var pkt = recvSocket!.read();
          if (pkt == null || pkt.length < 20) continue;
          
          // Parse IP header
          var ipHeader = ByteData.view(pkt.buffer, 0, 20);
          var protocol = ipHeader.getUint8(9);
          
          // Verify DART protocol
          if (protocol != DART_PROTOCOL) continue;
          
          // Parse DART header
          var dartStart = 20;
          if (pkt.length < dartStart + 4) continue;
          
          var version = pkt[dartStart];
          var upperProtocol = pkt[dartStart + 1];
          
          if (version != 1 || upperProtocol != ICMP_PROTOCOL) continue;
          
          var dstLen = pkt[dartStart + 2];
          var srcLen = pkt[dartStart + 3];
          
          if (pkt.length < dartStart + 4 + dstLen + srcLen) continue;
          
          var dstFqdn = utf8.decode(pkt.sublist(dartStart + 4, dartStart + 4 + dstLen));
          var srcFqdn = utf8.decode(pkt.sublist(dartStart + 4 + dstLen, dartStart + 4 + dstLen + srcLen));
          
          // Parse ICMP response
          var icmpStart = dartStart + 4 + dstLen + srcLen;
          if (pkt.length < icmpStart + 8) continue;
          
          var icmpType = pkt[icmpStart];
          var icmpCode = pkt[icmpStart + 1];
          
          if (icmpType == ICMP_ECHO_REPLY && icmpCode == 0) {
            var timestamp = ByteData.view(pkt.buffer, icmpStart + 8, 8).getFloat64(0, Endian.big);
            var rtt = (DateTime.now().millisecondsSinceEpoch / 1000 - timestamp) * 1000;
            var seq = ByteData.view(pkt.buffer, icmpStart + 6, 2).getUint16(0, Endian.big);
            
            rttList.add(rtt);
            recvCount++;
            
            return (
              seq: seq,
              rtt: rtt,
              addr: InternetAddress(ipHeader.getUint32(12, Endian.big).toString(),
              srcFqdn: srcFqdn,
              packet: pkt
            );
          }
        }
      }
    } on TimeoutException {
      // Timeout occurred
    }
    
    return (seq: null, rtt: null, addr: null, srcFqdn: null, packet: null);
  }
  
  void close() {
    sendSocket?.close();
    recvSocket?.close();
  }
}

Future<String> getDhcpDomainName() async {
  // Try resolvectl first
  try {
    var result = await Process.run('resolvectl', ['status']);
    if (result.exitCode == 0) {
      var output = result.stdout.toString();
      var lines = output.split('\n');
      for (var line in lines) {
        if (line.contains('DNS Domain')) {
          var domain = line.split(':').last.trim();
          if (domain.isNotEmpty) return domain;
        }
      }
    }
  } catch (e) {
    print('resolvectl error: $e');
  }
  
  // Fallback to /etc/resolv.conf
  try {
    var file = File('/etc/resolv.conf');
    var lines = await file.readAsLines();
    for (var line in lines) {
      if (line.startsWith('search') || line.startsWith('domain')) {
        var parts = line.trim().split(RegExp(r'\s+'));
        if (parts.length >= 2) return parts[1];
      }
    }
  } catch (e) {
    print('resolv.conf error: $e');
  }
  
  return '';
}

void signalHandler() {
  print('\n--- ping statistics ---');
  var loss = 100 * (pinger.sentCount - pinger.recvCount) / pinger.sentCount;
  print('${pinger.sentCount} packets transmitted, ${pinger.recvCount} received, '
      '${loss.toStringAsFixed(1)}% packet loss');
  
  var validRtts = pinger.rttList.where((rtt) => rtt != null).cast<double>().toList();
  if (validRtts.isNotEmpty) {
    var min = validRtts.reduce(min);
    var max = validRtts.reduce(max);
    var avg = validRtts.reduce((a, b) => a + b) / validRtts.length;
    print('rtt min/avg/max = ${min.toStringAsFixed(2)}/'
        '${avg.toStringAsFixed(2)}/'
        '${max.toStringAsFixed(2)} ms');
  }
  
  pinger.close();
  exit(0);
}

DARTPinger pinger = DARTPinger('', '');

Future<void> main(List<String> arguments) async {
  var parser = ArgParser();
  parser.addOption('target', abbr: 't', help: 'Target FQDN address');
  parser.addOption('interval', abbr: 'i', defaultsTo: '1', help: 'Interval between packets');
  parser.addOption('timeout', defaultsTo: '2', help: 'Response timeout in seconds');
  parser.addOption('ttl', defaultsTo: '64', help: 'Time To Live');
  
  var results = parser.parse(arguments);
  
  if (results['target'] == null) {
    print('Usage: dart_ping.dart --target example.com');
    exit(1);
  }
  
  var target = results['target']!;
  var interval = double.parse(results['interval']);
  var timeout = int.parse(results['timeout']);
  var ttl = int.parse(results['ttl']);
  
  // Get local FQDN
  var domain = await getDhcpDomainName();
  var hostname = Platform.localHostname;
  var srcFqdn = domain.isNotEmpty ? '$hostname.$domain' : hostname;
  
  pinger = DARTPinger(target, srcFqdn, ttl: ttl, timeout: timeout);
  
  // Set up signal handler
  ProcessSignal.sigint.watch().listen((_) => signalHandler());
  
  var ip = (await InternetAddress.lookup(target)).first.address;
  print('PING $target ($ip) via DART protocol');
  
  var seq = 0;
  
  while (true) {
    var sendTime = await pinger.sendPacket(seq);
    var startTime = DateTime.now().millisecondsSinceEpoch / 1000;
    var timeoutOccurred = true;
    
    while (true) {
      var elapsed = DateTime.now().millisecondsSinceEpoch / 1000 - startTime;
      if (elapsed > timeout) {
        print('Request timeout for icmp_seq $seq');
        break;
      }
      
      var response = await pinger.recvResponse();
      if (response.seq == seq) {
        print('${response.packet?.length} bytes from ${response.srcFqdn} (${response.addr}): '
            'icmp_seq=$seq ttl=$ttl time=${response.rtt?.toStringAsFixed(2)} ms');
        timeoutOccurred = false;
        break;
      }
    }
    
    if (timeoutOccurred) {
      pinger.rttList.add(null);
    }
    
    seq++;
    await Future.delayed(Duration(milliseconds: (interval * 1000).round()));
  }
}