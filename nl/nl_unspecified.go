// +build !linux

// Package nl has low level primitives for making Netlink calls.
package nl

import (
	"encoding/binary"
	"net"
	"sync"
	"unsafe"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	// Family type definitions
	FAMILY_ALL  = unix.AF_UNSPEC
	FAMILY_V4   = unix.AF_INET
	FAMILY_V6   = unix.AF_INET6
	FAMILY_MPLS = AF_MPLS
	// Arbitrary set value (greater than default 4k) to allow receiving
	// from kernel more verbose messages e.g. for statistics,
	// tc rules or filters, or other more memory requiring data.
	RECEIVE_BUFFER_SIZE = 65536
)

// SupportedNlFamilies contains the list of netlink families this netlink package supports
var SupportedNlFamilies = []int{}

var nextSeqNr uint32

// GetIPFamily returns the family type of a net.IP.
func GetIPFamily(ip net.IP) int {
	if len(ip) <= net.IPv4len {
		return FAMILY_V4
	}
	if ip.To4() != nil {
		return FAMILY_V4
	}
	return FAMILY_V6
}

var nativeEndian binary.ByteOrder

// Get native endianness for the system
func NativeEndian() binary.ByteOrder {
	if nativeEndian == nil {
		var x uint32 = 0x01020304
		if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
			nativeEndian = binary.BigEndian
		} else {
			nativeEndian = binary.LittleEndian
		}
	}
	return nativeEndian
}

// Byte swap a 16 bit value if we aren't big endian
func Swap16(i uint16) uint16 {
	if NativeEndian() == binary.BigEndian {
		return i
	}
	return (i&0xff00)>>8 | (i&0xff)<<8
}

// Byte swap a 32 bit value if aren't big endian
func Swap32(i uint32) uint32 {
	if NativeEndian() == binary.BigEndian {
		return i
	}
	return (i&0xff000000)>>24 | (i&0xff0000)>>8 | (i&0xff00)<<8 | (i&0xff)<<24
}

type NetlinkRequestData interface {
	Len() int
	Serialize() []byte
}

// IfInfomsg is related to links, but it is used for list requests as well
type IfInfomsg struct {
}

// Create an IfInfomsg with family specified
func NewIfInfomsg(family int) *IfInfomsg {
	panic("not implemented")
}

func DeserializeIfInfomsg(b []byte) *IfInfomsg {
	panic("not implemented")
}

func (msg *IfInfomsg) Serialize() []byte {
	panic("not implemented")
}

func (msg *IfInfomsg) Len() int {
	panic("not implemented")
}

func (msg *IfInfomsg) EncapType() string {
	panic("not implemented")
}

func rtaAlignOf(attrlen int) int {
	panic("not implemented")
}

func NewIfInfomsgChild(parent *RtAttr, family int) *IfInfomsg {
	panic("not implemented")
}

// Extend RtAttr to handle data and children
type RtAttr struct {
	Data     []byte
	children []NetlinkRequestData
}

// Create a new Extended RtAttr object
func NewRtAttr(attrType int, data []byte) *RtAttr {
	panic("not implemented")
}

// Create a new RtAttr obj anc add it as a child of an existing object
func NewRtAttrChild(parent *RtAttr, attrType int, data []byte) *RtAttr {
	panic("not implemented")
}

// AddChild adds an existing RtAttr as a child.
func (a *RtAttr) AddChild(attr *RtAttr) {
	panic("not implemented")
}

func (a *RtAttr) Len() int {
	panic("not implemented")
}

// Serialize the RtAttr into a byte array
// This can't just unsafe.cast because it must iterate through children.
func (a *RtAttr) Serialize() []byte {
	panic("not implemented")
}

type NetlinkRequest struct {
	Data    []NetlinkRequestData
	RawData []byte
	Sockets map[int]*SocketHandle
}

// Serialize the Netlink Request into a byte array
func (req *NetlinkRequest) Serialize() []byte {
	panic("not implemented")
}

func (req *NetlinkRequest) AddData(data NetlinkRequestData) {
	panic("not implemented")
}

// AddRawData adds raw bytes to the end of the NetlinkRequest object during serialization
func (req *NetlinkRequest) AddRawData(data []byte) {
	if data != nil {
		req.RawData = append(req.RawData, data...)
	}
}

// Execute the request against a the given sockType.
// Returns a list of netlink messages in serialized format, optionally filtered
// by resType.
func (req *NetlinkRequest) Execute(sockType int, resType uint16) ([][]byte, error) {
	panic("not implemented")
}

// Create a new netlink request from proto and flags
// Note the Len value will be inaccurate once data is added until
// the message is serialized
func NewNetlinkRequest(proto, flags int) *NetlinkRequest {
	panic("not implemented")
}

type NetlinkSocket struct {
	fd int32
	sync.Mutex
}

func getNetlinkSocket(protocol int) (*NetlinkSocket, error) {
	panic("not implemented")
}

// GetNetlinkSocketAt opens a netlink socket in the network namespace newNs
// and positions the thread back into the network namespace specified by curNs,
// when done. If curNs is close, the function derives the current namespace and
// moves back into it when done. If newNs is close, the socket will be opened
// in the current network namespace.
func GetNetlinkSocketAt(newNs, curNs netns.NsHandle, protocol int) (*NetlinkSocket, error) {
	panic("not implemented")
}

// executeInNetns sets execution of the code following this call to the
// network namespace newNs, then moves the thread back to curNs if open,
// otherwise to the current netns at the time the function was invoked
// In case of success, the caller is expected to execute the returned function
// at the end of the code that needs to be executed in the network namespace.
// Example:
// func jobAt(...) error {
//      d, err := executeInNetns(...)
//      if err != nil { return err}
//      defer d()
//      < code which needs to be executed in specific netns>
//  }
// TODO: his function probably belongs to netns pkg.
func executeInNetns(newNs, curNs netns.NsHandle) (func(), error) {
	panic("not implemented")
}

// Create a netlink socket with a given protocol (e.g. NETLINK_ROUTE)
// and subscribe it to multicast groups passed in variable argument list.
// Returns the netlink socket on which Receive() method can be called
// to retrieve the messages from the kernel.
func Subscribe(protocol int, groups ...uint) (*NetlinkSocket, error) {
	panic("not implemented")
}

// SubscribeAt works like Subscribe plus let's the caller choose the network
// namespace in which the socket would be opened (newNs). Then control goes back
// to curNs if open, otherwise to the netns at the time this function was called.
func SubscribeAt(newNs, curNs netns.NsHandle, protocol int, groups ...uint) (*NetlinkSocket, error) {
	panic("not implemented")
}

func (s *NetlinkSocket) Close() {
	panic("not implemented")
}

func (s *NetlinkSocket) GetFd() int {
	panic("not implemented")
}

func (s *NetlinkSocket) Send(request *NetlinkRequest) error {
	panic("not implemented")
}

// func (s *NetlinkSocket) Receive() ([]syscall.NetlinkMessage, error) {
// 	panic("not implemented")
// }

// SetSendTimeout allows to set a send timeout on the socket
func (s *NetlinkSocket) SetSendTimeout(timeout *unix.Timeval) error {
	panic("not implemented")
}

// SetReceiveTimeout allows to set a receive timeout on the socket
func (s *NetlinkSocket) SetReceiveTimeout(timeout *unix.Timeval) error {
	panic("not implemented")
}

func (s *NetlinkSocket) GetPid() (uint32, error) {
	panic("not implemented")
}

func ZeroTerminated(s string) []byte {
	panic("not implemented")
}

func NonZeroTerminated(s string) []byte {
	panic("not implemented")
}

func BytesToString(b []byte) string {
	panic("not implemented")
}

func Uint8Attr(v uint8) []byte {
	panic("not implemented")
}

func Uint16Attr(v uint16) []byte {
	panic("not implemented")
}

func Uint32Attr(v uint32) []byte {
	panic("not implemented")
}

func Uint64Attr(v uint64) []byte {
	panic("not implemented")
}

func Uint16AttrNetEndian(v uint16) []byte {
	panic("not implemented")
}

func Uint32AttrNetEndian(v uint32) []byte {
	panic("not implemented")
}

func ParseZeroTerminated(data []byte) string {
	panic("not implemented")
}

// func ParseRouteAttr(b []byte) ([]syscall.NetlinkRouteAttr, error) {
// 	panic("not implemented")
// }

// func netlinkRouteAttrAndValue(b []byte) (*unix.RtAttr, []byte, int, error) {
// 	panic("not implemented")
// }

// SocketHandle contains the netlink socket and the associated
// sequence counter for a specific netlink family
type SocketHandle struct {
	Seq    uint32
	Socket *NetlinkSocket
}

// Close closes the netlink socket
func (sh *SocketHandle) Close() {
	panic("not implemented")
}
