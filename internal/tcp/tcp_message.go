package tcp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/buger/goreplay/proto"
	"net"
	"reflect"
	"sort"
	"time"
	"unsafe"
)

// TCPProtocol is a number to indicate type of protocol
type TCPProtocol uint8

const (
	// ProtocolHTTP ...
	ProtocolHTTP TCPProtocol = iota
	// ProtocolBinary ...
	ProtocolBinary
)

// Set is here so that TCPProtocol can implement flag.Var
func (protocol *TCPProtocol) Set(v string) error {
	switch v {
	case "", "http":
		*protocol = ProtocolHTTP
	case "binary":
		*protocol = ProtocolBinary
	default:
		return fmt.Errorf("unsupported protocol %s", v)
	}
	return nil
}

func (protocol *TCPProtocol) String() string {
	switch *protocol {
	case ProtocolBinary:
		return "binary"
	case ProtocolHTTP:
		return "http"
	default:
		return ""
	}
}

// Stats every message carry its own stats object
type Stats struct {
	LostData  int
	Length    int       // length of the data
	Start     time.Time // first packet's timestamp
	End       time.Time // last packet's timestamp
	SrcAddr   string
	DstAddr   string
	Direction Dir
	TimedOut  bool // timeout before getting the whole message
	Truncated bool // last packet truncated due to max message size
	IPversion byte
}

// Message is the representation of a tcp message
type Message struct {
	packets          []*Packet
	parser           *MessageParser
	feedback         interface{}
	continueAdjusted bool
	Stats
}

// UUID returns the UUID of a TCP request and its response.
func (m *Message) UUID() []byte {
	var streamID uint64
	pckt := m.packets[0]

	// check if response or request have generated the ID before.
	if m.Direction == DirIncoming {
		streamID = uint64(pckt.SrcPort)<<48 | uint64(pckt.DstPort)<<32 |
			uint64(ip2int(pckt.SrcIP))
	} else {
		streamID = uint64(pckt.DstPort)<<48 | uint64(pckt.SrcPort)<<32 |
			uint64(ip2int(pckt.DstIP))
	}

	id := make([]byte, 12)
	binary.BigEndian.PutUint64(id, streamID)

	if m.Direction == DirIncoming {
		binary.BigEndian.PutUint32(id[8:], pckt.Ack)
	} else {
		binary.BigEndian.PutUint32(id[8:], pckt.Seq)
	}

	uuidHex := make([]byte, 24)
	hex.Encode(uuidHex[:], id[:])

	return uuidHex
}

// ME：TCP报文到达的先后顺序不一定，根据seq将报文按顺序加入到队列，确保最终报文有序。
func (m *Message) add(packet *Packet) bool {
	// Skip duplicates
	for _, p := range m.packets {
		if p.Seq == packet.Seq {
			return false
		}
	}

	// Packets not always captured in same Seq order, and sometimes we need to prepend
	if len(m.packets) == 0 || packet.Seq > m.packets[len(m.packets)-1].Seq {
		m.packets = append(m.packets, packet)
	} else if packet.Seq < m.packets[0].Seq {
		m.packets = append([]*Packet{packet}, m.packets...)
	} else { // insert somewhere in the middle...
		for i, p := range m.packets {
			if packet.Seq < p.Seq {
				m.packets = append(m.packets[:i], append([]*Packet{packet}, m.packets[i:]...)...)
				break
			}
		}
	}

	m.Length += len(packet.Payload)
	m.LostData += int(packet.Lost)

	if packet.Timestamp.After(m.End) || m.End.IsZero() {
		m.End = packet.Timestamp
	}

	return true
}

// Packets returns packets of the message
func (m *Message) Packets() []*Packet {
	return m.packets
}

// 检查有没有丢IP包，注意Seq含义，统计的是TCP包内数据的长度，不包括包头的长度。
// If a TCP packet contains 1400 bytes of data, then the sequence number will be increased by 1400 after the packet is transmitted.
func (m *Message) MissingChunk() bool {
	nextSeq := m.packets[0].Seq

	for _, p := range m.packets {
		if p.Seq != nextSeq {
			return true
		}

		nextSeq += uint32(len(p.Payload))
	}

	return false
}

// 每一个TCP包的数据。
func (m *Message) PacketData() [][]byte {
	tmp := make([][]byte, len(m.packets))

	for i, p := range m.packets {
		tmp[i] = p.Payload
	}

	return tmp
}

// Data returns data in this message
func (m *Message) Data() []byte {
	packetData := m.PacketData()
	tmp := packetData[0]

	if len(packetData) > 0 {
		tmp, _ = copySlice(tmp, len(packetData[0]), packetData[1:]...)
	}

	// Remove Expect header, since its replay not fully supported
	if state, ok := m.feedback.(*proto.HTTPState); ok {
		if state.Continue100 {
			tmp = proto.DeleteHeader(tmp, []byte("Expect"))
		}
	}

	return tmp
}

// SetProtocolState set feedback/data that can be used later, e.g with End or Start hint
func (m *Message) SetProtocolState(feedback interface{}) {
	m.feedback = feedback
}

// ProtocolState returns feedback associated to this message
func (m *Message) ProtocolState() interface{} {
	return m.feedback
}

// Sort a helper to sort packets
func (m *Message) Sort() {
	sort.SliceStable(m.packets, func(i, j int) bool { return m.packets[i].Seq < m.packets[j].Seq })
}

// Emitter message handler
type Emitter func(*Message)

// HintEnd hints the parser to stop the session, see MessageParser.End
// when set, it will be executed before checking FIN or RST flag
type HintEnd func(*Message) bool

// HintStart hints the parser to start the reassembling the message, see MessageParser.Start
// when set, it will be called after checking SYN flag
type HintStart func(*Packet) (IsRequest, IsOutgoing bool)

// MessageParser holds data of all tcp messages in progress(still receiving/sending packets).
// message is identified by its source port and dst port, and last 4bytes of src IP.
type MessageParser struct {
	m map[uint64]*Message // ME：组装过程中的TCP数据包

	messageExpire  time.Duration // the maximum time to wait for the final packet, minimum is 1000ms
	allowIncompete bool
	End            HintEnd   // 一个TCP数据包接收结束
	Start          HintStart // 一个TCP数据包接收开始
	ticker         *time.Ticker
	messages       chan *Message    // ME：多个IP包组装后的一个完整的TCP数据包
	packets        chan *PcapPacket // ME: 收到的IP数据包
	close          chan struct{}    // to signal that we are able to close
	ports          []uint16         // ME：本服务所在监听的端口，若数据包的srcPort在列表中，则数据包为出数据包，如果dstPort在ports列表中，则为入数据包
	ips            []net.IP         // ME：本服务所在监听的IP，若数据包的srcIP在列表中，则数据包为出数据包，如果dstIP在ports列表中，则为入数据包。 ports和ips需要组合起来判断。
}

// NewMessageParser returns a new instance of message parser
// ME：New完之后就开始监听并记录数据了。
func NewMessageParser(messages chan *Message, ports []uint16, ips []net.IP, messageExpire time.Duration, allowIncompete bool) (parser *MessageParser) {
	parser = new(MessageParser)

	parser.messageExpire = messageExpire
	if parser.messageExpire == 0 {
		parser.messageExpire = time.Millisecond * 1000
	}

	parser.allowIncompete = allowIncompete

	parser.packets = make(chan *PcapPacket, 10000)

	if messages == nil {
		messages = make(chan *Message, 1000)
	}
	parser.messages = messages

	parser.m = make(map[uint64]*Message)
	parser.ticker = time.NewTicker(time.Millisecond * 100)
	parser.close = make(chan struct{}, 1)

	parser.ports = ports
	parser.ips = ips

	go parser.wait()
	return parser
}

var packetLen int

// Packet returns packet handler
func (parser *MessageParser) PacketHandler(packet *PcapPacket) {
	packetLen++
	parser.packets <- packet
}

func (parser *MessageParser) wait() {
	var (
		now time.Time
	)
	for {
		select {
		case pckt := <-parser.packets:
			parser.processPacket(parser.parsePacket(pckt))
		case now = <-parser.ticker.C:
			parser.timer(now)
		case <-parser.close:
			parser.ticker.Stop()
			// parser.Close should wait for this function to return
			parser.close <- struct{}{}
			return
			// default:
		}
	}
}

// ME： 解析原生IP数据包，得到解析后的IP包。
func (parser *MessageParser) parsePacket(pcapPkt *PcapPacket) *Packet {
	pckt, err := ParsePacket(pcapPkt.Data, pcapPkt.LType, pcapPkt.LTypeLen, pcapPkt.Ci, false)
	if err != nil {
		if _, empty := err.(EmptyPacket); !empty {
			stats.Add("packet_error", 1)
		}
		return nil
	}

	for _, p := range parser.ports {
		if pckt.DstPort == p && containsOrEmpty(pckt.DstIP, parser.ips) {
			pckt.Direction = DirIncoming
			break
		} else if pckt.SrcPort == p && containsOrEmpty(pckt.SrcIP, parser.ips) {
			pckt.Direction = DirOutcoming
			break
		}
	}

	return pckt
}

func containsOrEmpty(element net.IP, ipList []net.IP) bool {
	if len(ipList) == 0 {
		return true
	}
	for _, ip := range ipList {
		if ip.Equal(element) {
			return true
		}
	}
	return false
}

// ME：处理解析后的IP包，组装成TCP包。
func (parser *MessageParser) processPacket(pckt *Packet) {
	if pckt == nil {
		return
	}

	// Trying to build unique hash, but there is small chance of collision
	// No matter if it is request or response, all packets in the same message have same
	m, ok := parser.m[pckt.MessageID()]
	switch {
	case ok: // 如果Message里已经有IP包，则将新收到的IP包加到Message里。
		if m.Direction == DirUnknown {
			if in, out := parser.Start(pckt); in || out {
				if in {
					m.Direction = DirIncoming
				} else {
					m.Direction = DirOutcoming
				}
			}
		}
		parser.addPacket(m, pckt)
		return
	case pckt.Direction == DirUnknown && parser.Start != nil: // ME：如果收到的包是第一个包，则new一个message处理。
		if in, out := parser.Start(pckt); in || out {
			if in {
				pckt.Direction = DirIncoming
			} else {
				pckt.Direction = DirOutcoming
			}
		}
	}

	m = new(Message)
	m.Direction = pckt.Direction
	m.SrcAddr = pckt.SrcIP.String()
	m.DstAddr = pckt.DstIP.String()

	parser.m[pckt.MessageID()] = m

	m.Start = pckt.Timestamp
	m.parser = parser
	parser.addPacket(m, pckt)
}

// ME：因为TCP包会拆分到多个IP包中传输，收到后需要根据ID将同一个TCP包组合到一起。
func (parser *MessageParser) addPacket(m *Message, pckt *Packet) bool {
	if !m.add(pckt) {
		return false
	}

	// If we are using protocol parsing, like HTTP, depend on its parsing func.
	// For the binary procols wait for message to expire
	if parser.End != nil {
		if parser.End(m) {
			parser.Emit(m) // ME：一个messageID的packet都处理完后，放到messageParser的Message中。
			return true
		}
		// 如果message还没结束，HTTP有一个Continue状态，需要处理下message。
		parser.Fix100Continue(m)
	}

	return true
}

// ME: 对于HTTP 100 Continue的包，需要额外处理下，然后将收到的message加入到messageParse的Map中。
func (parser *MessageParser) Fix100Continue(m *Message) {
	// Only adjust a message once
	if state, ok := m.feedback.(*proto.HTTPState); ok && state.Continue100 && !m.continueAdjusted {
		// Shift Ack by given offset
		// Size of "HTTP/1.1 100 Continue\r\n\r\n" message
		for _, p := range m.packets {
			p.messageID = 0
			p.Ack += 25
		}

		// If next section was aready approved and received, merge messages
		if next, found := parser.m[m.packets[0].MessageID()]; found {
			for _, p := range next.packets {
				parser.addPacket(m, p)
			}
		}

		// Re-add (or override) again with new message and ID
		parser.m[m.packets[0].MessageID()] = m
		m.continueAdjusted = true
	}
}

// ME：从messageParser里读取组装好的TCP包。
func (parser *MessageParser) Read() *Message {
	m := <-parser.messages
	return m
}

// ME：将组装好/正在组装的TCP包发给messageParser
func (parser *MessageParser) Emit(m *Message) {
	stats.Add("message_count", 1)

	delete(parser.m, m.packets[0].MessageID())

	parser.messages <- m
}

func GetUnexportedField(field reflect.Value) interface{} {
	return reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface()
}

var failMsg int

// ME：检查是否超过了IP包接收时间，超过则丢弃该TCP包或做其他处理。
func (parser *MessageParser) timer(now time.Time) {
	packetLen = 0

	packetQueueLen.Set(int64(len(parser.packets)))
	messageQueueLen.Set(int64(len(parser.m)))

	for _, m := range parser.m {
		if now.Sub(m.End) > parser.messageExpire {
			m.TimedOut = true
			stats.Add("message_timeout_count", 1)
			failMsg++
			if parser.End == nil || parser.allowIncompete {
				parser.Emit(m)
			}

			delete(parser.m, m.packets[0].MessageID())
		}
	}
}

func (parser *MessageParser) Close() error {
	parser.close <- struct{}{}
	<-parser.close // wait for timer to be closed!
	return nil
}
