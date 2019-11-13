// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: conf.proto

package conf

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type Server_Type int32

const (
	Server_Dummy Server_Type = 0
	Server_UDP   Server_Type = 1
	Server_DOH   Server_Type = 2
)

var Server_Type_name = map[int32]string{
	0: "Dummy",
	1: "UDP",
	2: "DOH",
}

var Server_Type_value = map[string]int32{
	"Dummy": 0,
	"UDP":   1,
	"DOH":   2,
}

func (x Server_Type) String() string {
	return proto.EnumName(Server_Type_name, int32(x))
}

func (Server_Type) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0b6ecbfc68e85c65, []int{1, 0}
}

type Config struct {
	Servers              []Server `protobuf:"bytes,1,rep,name=server,proto3" json:"server"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Config) Reset()         { *m = Config{} }
func (m *Config) String() string { return proto.CompactTextString(m) }
func (*Config) ProtoMessage()    {}
func (*Config) Descriptor() ([]byte, []int) {
	return fileDescriptor_0b6ecbfc68e85c65, []int{0}
}
func (m *Config) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Config) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Config.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Config) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Config.Merge(m, src)
}
func (m *Config) XXX_Size() int {
	return m.Size()
}
func (m *Config) XXX_DiscardUnknown() {
	xxx_messageInfo_Config.DiscardUnknown(m)
}

var xxx_messageInfo_Config proto.InternalMessageInfo

func (m *Config) GetServers() []Server {
	if m != nil {
		return m.Servers
	}
	return nil
}

type Server struct {
	Name                 string      `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Type                 Server_Type `protobuf:"varint,2,opt,name=type,proto3,enum=conf.Server_Type" json:"type,omitempty"`
	HostPort             string      `protobuf:"bytes,3,opt,name=host_port,json=hostPort,proto3" json:"host_port,omitempty"`
	DohUrl               string      `protobuf:"bytes,4,opt,name=doh_url,json=dohUrl,proto3" json:"doh_url,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *Server) Reset()         { *m = Server{} }
func (m *Server) String() string { return proto.CompactTextString(m) }
func (*Server) ProtoMessage()    {}
func (*Server) Descriptor() ([]byte, []int) {
	return fileDescriptor_0b6ecbfc68e85c65, []int{1}
}
func (m *Server) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Server) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Server.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Server) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Server.Merge(m, src)
}
func (m *Server) XXX_Size() int {
	return m.Size()
}
func (m *Server) XXX_DiscardUnknown() {
	xxx_messageInfo_Server.DiscardUnknown(m)
}

var xxx_messageInfo_Server proto.InternalMessageInfo

func (m *Server) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Server) GetType() Server_Type {
	if m != nil {
		return m.Type
	}
	return Server_Dummy
}

func (m *Server) GetHostPort() string {
	if m != nil {
		return m.HostPort
	}
	return ""
}

func (m *Server) GetDohUrl() string {
	if m != nil {
		return m.DohUrl
	}
	return ""
}

func init() {
	proto.RegisterEnum("conf.Server_Type", Server_Type_name, Server_Type_value)
	proto.RegisterType((*Config)(nil), "conf.Config")
	proto.RegisterType((*Server)(nil), "conf.Server")
}

func init() { proto.RegisterFile("conf.proto", fileDescriptor_0b6ecbfc68e85c65) }

var fileDescriptor_0b6ecbfc68e85c65 = []byte{
	// 251 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4a, 0xce, 0xcf, 0x4b,
	0xd3, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x01, 0xb1, 0xa5, 0x44, 0xd2, 0xf3, 0xd3, 0xf3,
	0xc1, 0x02, 0xfa, 0x20, 0x16, 0x44, 0x4e, 0xc9, 0x9e, 0x8b, 0xcd, 0x39, 0x3f, 0x2f, 0x2d, 0x33,
	0x5d, 0xc8, 0x94, 0x8b, 0xad, 0x38, 0xb5, 0xa8, 0x2c, 0xb5, 0x48, 0x82, 0x51, 0x81, 0x59, 0x83,
	0xdb, 0x88, 0x47, 0x0f, 0x6c, 0x44, 0x30, 0x58, 0xcc, 0x89, 0xff, 0xc4, 0x3d, 0x79, 0x86, 0x47,
	0xf7, 0xe4, 0xd9, 0x21, 0xfc, 0xe2, 0x20, 0xa8, 0x62, 0xa5, 0x79, 0x8c, 0x5c, 0x6c, 0x10, 0x31,
	0x21, 0x21, 0x2e, 0x96, 0xbc, 0xc4, 0xdc, 0x54, 0x09, 0x46, 0x05, 0x46, 0x0d, 0xce, 0x20, 0x30,
	0x5b, 0x48, 0x95, 0x8b, 0xa5, 0xa4, 0xb2, 0x20, 0x55, 0x82, 0x49, 0x81, 0x51, 0x83, 0xcf, 0x48,
	0x10, 0xd9, 0x4c, 0xbd, 0x90, 0xca, 0x82, 0xd4, 0x20, 0xb0, 0xb4, 0x90, 0x34, 0x17, 0x67, 0x46,
	0x7e, 0x71, 0x49, 0x7c, 0x41, 0x7e, 0x51, 0x89, 0x04, 0x33, 0x58, 0x3f, 0x07, 0x48, 0x20, 0x20,
	0xbf, 0xa8, 0x44, 0x48, 0x9c, 0x8b, 0x3d, 0x25, 0x3f, 0x23, 0xbe, 0xb4, 0x28, 0x47, 0x82, 0x05,
	0x2c, 0xc5, 0x96, 0x92, 0x9f, 0x11, 0x5a, 0x94, 0xa3, 0xa4, 0xcc, 0xc5, 0x02, 0x32, 0x43, 0x88,
	0x93, 0x8b, 0xd5, 0xa5, 0x34, 0x37, 0xb7, 0x52, 0x80, 0x41, 0x88, 0x9d, 0x8b, 0x39, 0xd4, 0x25,
	0x40, 0x80, 0x11, 0xc4, 0x70, 0xf1, 0xf7, 0x10, 0x60, 0x72, 0xe2, 0x39, 0xf1, 0x48, 0x8e, 0xf1,
	0xc2, 0x23, 0x39, 0xc6, 0x07, 0x8f, 0xe4, 0x18, 0x93, 0xd8, 0xc0, 0xde, 0x36, 0x06, 0x04, 0x00,
	0x00, 0xff, 0xff, 0x9f, 0x01, 0x6e, 0xad, 0x20, 0x01, 0x00, 0x00,
}

func (m *Config) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Config) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Config) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.Servers) > 0 {
		for iNdEx := len(m.Servers) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Servers[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintConf(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func (m *Server) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Server) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Server) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.DohUrl) > 0 {
		i -= len(m.DohUrl)
		copy(dAtA[i:], m.DohUrl)
		i = encodeVarintConf(dAtA, i, uint64(len(m.DohUrl)))
		i--
		dAtA[i] = 0x22
	}
	if len(m.HostPort) > 0 {
		i -= len(m.HostPort)
		copy(dAtA[i:], m.HostPort)
		i = encodeVarintConf(dAtA, i, uint64(len(m.HostPort)))
		i--
		dAtA[i] = 0x1a
	}
	if m.Type != 0 {
		i = encodeVarintConf(dAtA, i, uint64(m.Type))
		i--
		dAtA[i] = 0x10
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintConf(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintConf(dAtA []byte, offset int, v uint64) int {
	offset -= sovConf(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Config) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Servers) > 0 {
		for _, e := range m.Servers {
			l = e.Size()
			n += 1 + l + sovConf(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *Server) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovConf(uint64(l))
	}
	if m.Type != 0 {
		n += 1 + sovConf(uint64(m.Type))
	}
	l = len(m.HostPort)
	if l > 0 {
		n += 1 + l + sovConf(uint64(l))
	}
	l = len(m.DohUrl)
	if l > 0 {
		n += 1 + l + sovConf(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovConf(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozConf(x uint64) (n int) {
	return sovConf(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Config) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConf
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Config: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Config: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Servers", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConf
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConf
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConf
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Servers = append(m.Servers, Server{})
			if err := m.Servers[len(m.Servers)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConf(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConf
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthConf
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Server) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConf
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Server: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Server: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConf
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConf
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConf
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			m.Type = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConf
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Type |= Server_Type(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field HostPort", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConf
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConf
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConf
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.HostPort = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DohUrl", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConf
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConf
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConf
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.DohUrl = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConf(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConf
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthConf
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipConf(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowConf
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConf
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConf
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthConf
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupConf
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthConf
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthConf        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowConf          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupConf = fmt.Errorf("proto: unexpected end of group")
)
