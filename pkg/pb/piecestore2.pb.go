// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: piecestore2.proto

package pb

import (
	context "context"
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/golang/protobuf/ptypes/duration"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// Expected order of messages from uplink:
//   OrderLimit ->
//   repeated
//      Order ->
//      Chunk ->
//   PieceHash signed by uplink ->
//      <- PieceHash signed by storage node
//
type PieceUploadRequest struct {
	// first message to show that we are allowed to upload
	Limit *OrderLimit2 `protobuf:"bytes,1,opt,name=limit,proto3" json:"limit,omitempty"`
	// order for uploading
	Order *Order2                   `protobuf:"bytes,2,opt,name=order,proto3" json:"order,omitempty"`
	Chunk *PieceUploadRequest_Chunk `protobuf:"bytes,3,opt,name=chunk,proto3" json:"chunk,omitempty"`
	// final message
	Done                 *PieceHash `protobuf:"bytes,4,opt,name=done,proto3" json:"done,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *PieceUploadRequest) Reset()         { *m = PieceUploadRequest{} }
func (m *PieceUploadRequest) String() string { return proto.CompactTextString(m) }
func (*PieceUploadRequest) ProtoMessage()    {}
func (*PieceUploadRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_23ff32dd550c2439, []int{0}
}
func (m *PieceUploadRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PieceUploadRequest.Unmarshal(m, b)
}
func (m *PieceUploadRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PieceUploadRequest.Marshal(b, m, deterministic)
}
func (m *PieceUploadRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PieceUploadRequest.Merge(m, src)
}
func (m *PieceUploadRequest) XXX_Size() int {
	return xxx_messageInfo_PieceUploadRequest.Size(m)
}
func (m *PieceUploadRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PieceUploadRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PieceUploadRequest proto.InternalMessageInfo

func (m *PieceUploadRequest) GetLimit() *OrderLimit2 {
	if m != nil {
		return m.Limit
	}
	return nil
}

func (m *PieceUploadRequest) GetOrder() *Order2 {
	if m != nil {
		return m.Order
	}
	return nil
}

func (m *PieceUploadRequest) GetChunk() *PieceUploadRequest_Chunk {
	if m != nil {
		return m.Chunk
	}
	return nil
}

func (m *PieceUploadRequest) GetDone() *PieceHash {
	if m != nil {
		return m.Done
	}
	return nil
}

// data message
type PieceUploadRequest_Chunk struct {
	Offset               int64    `protobuf:"varint,1,opt,name=offset,proto3" json:"offset,omitempty"`
	Data                 []byte   `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PieceUploadRequest_Chunk) Reset()         { *m = PieceUploadRequest_Chunk{} }
func (m *PieceUploadRequest_Chunk) String() string { return proto.CompactTextString(m) }
func (*PieceUploadRequest_Chunk) ProtoMessage()    {}
func (*PieceUploadRequest_Chunk) Descriptor() ([]byte, []int) {
	return fileDescriptor_23ff32dd550c2439, []int{0, 0}
}
func (m *PieceUploadRequest_Chunk) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PieceUploadRequest_Chunk.Unmarshal(m, b)
}
func (m *PieceUploadRequest_Chunk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PieceUploadRequest_Chunk.Marshal(b, m, deterministic)
}
func (m *PieceUploadRequest_Chunk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PieceUploadRequest_Chunk.Merge(m, src)
}
func (m *PieceUploadRequest_Chunk) XXX_Size() int {
	return xxx_messageInfo_PieceUploadRequest_Chunk.Size(m)
}
func (m *PieceUploadRequest_Chunk) XXX_DiscardUnknown() {
	xxx_messageInfo_PieceUploadRequest_Chunk.DiscardUnknown(m)
}

var xxx_messageInfo_PieceUploadRequest_Chunk proto.InternalMessageInfo

func (m *PieceUploadRequest_Chunk) GetOffset() int64 {
	if m != nil {
		return m.Offset
	}
	return 0
}

func (m *PieceUploadRequest_Chunk) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type PieceUploadResponse struct {
	Done                 *PieceHash `protobuf:"bytes,1,opt,name=done,proto3" json:"done,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *PieceUploadResponse) Reset()         { *m = PieceUploadResponse{} }
func (m *PieceUploadResponse) String() string { return proto.CompactTextString(m) }
func (*PieceUploadResponse) ProtoMessage()    {}
func (*PieceUploadResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_23ff32dd550c2439, []int{1}
}
func (m *PieceUploadResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PieceUploadResponse.Unmarshal(m, b)
}
func (m *PieceUploadResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PieceUploadResponse.Marshal(b, m, deterministic)
}
func (m *PieceUploadResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PieceUploadResponse.Merge(m, src)
}
func (m *PieceUploadResponse) XXX_Size() int {
	return xxx_messageInfo_PieceUploadResponse.Size(m)
}
func (m *PieceUploadResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PieceUploadResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PieceUploadResponse proto.InternalMessageInfo

func (m *PieceUploadResponse) GetDone() *PieceHash {
	if m != nil {
		return m.Done
	}
	return nil
}

// Expected order of messages from uplink:
//   {OrderLimit, Chunk} ->
//   go repeated
//      Order -> (async)
//   go repeated
//      <- PieceDownloadResponse.Chunk
type PieceDownloadRequest struct {
	// first message to show that we are allowed to upload
	Limit *OrderLimit2 `protobuf:"bytes,1,opt,name=limit,proto3" json:"limit,omitempty"`
	// order for downloading
	Order *Order2 `protobuf:"bytes,2,opt,name=order,proto3" json:"order,omitempty"`
	// request for the chunk
	Chunk                *PieceDownloadRequest_Chunk `protobuf:"bytes,3,opt,name=chunk,proto3" json:"chunk,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                    `json:"-"`
	XXX_unrecognized     []byte                      `json:"-"`
	XXX_sizecache        int32                       `json:"-"`
}

func (m *PieceDownloadRequest) Reset()         { *m = PieceDownloadRequest{} }
func (m *PieceDownloadRequest) String() string { return proto.CompactTextString(m) }
func (*PieceDownloadRequest) ProtoMessage()    {}
func (*PieceDownloadRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_23ff32dd550c2439, []int{2}
}
func (m *PieceDownloadRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PieceDownloadRequest.Unmarshal(m, b)
}
func (m *PieceDownloadRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PieceDownloadRequest.Marshal(b, m, deterministic)
}
func (m *PieceDownloadRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PieceDownloadRequest.Merge(m, src)
}
func (m *PieceDownloadRequest) XXX_Size() int {
	return xxx_messageInfo_PieceDownloadRequest.Size(m)
}
func (m *PieceDownloadRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PieceDownloadRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PieceDownloadRequest proto.InternalMessageInfo

func (m *PieceDownloadRequest) GetLimit() *OrderLimit2 {
	if m != nil {
		return m.Limit
	}
	return nil
}

func (m *PieceDownloadRequest) GetOrder() *Order2 {
	if m != nil {
		return m.Order
	}
	return nil
}

func (m *PieceDownloadRequest) GetChunk() *PieceDownloadRequest_Chunk {
	if m != nil {
		return m.Chunk
	}
	return nil
}

// Chunk that we wish to download
type PieceDownloadRequest_Chunk struct {
	Offset               int64    `protobuf:"varint,1,opt,name=offset,proto3" json:"offset,omitempty"`
	ChunkSize            int64    `protobuf:"varint,2,opt,name=chunk_size,json=chunkSize,proto3" json:"chunk_size,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PieceDownloadRequest_Chunk) Reset()         { *m = PieceDownloadRequest_Chunk{} }
func (m *PieceDownloadRequest_Chunk) String() string { return proto.CompactTextString(m) }
func (*PieceDownloadRequest_Chunk) ProtoMessage()    {}
func (*PieceDownloadRequest_Chunk) Descriptor() ([]byte, []int) {
	return fileDescriptor_23ff32dd550c2439, []int{2, 0}
}
func (m *PieceDownloadRequest_Chunk) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PieceDownloadRequest_Chunk.Unmarshal(m, b)
}
func (m *PieceDownloadRequest_Chunk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PieceDownloadRequest_Chunk.Marshal(b, m, deterministic)
}
func (m *PieceDownloadRequest_Chunk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PieceDownloadRequest_Chunk.Merge(m, src)
}
func (m *PieceDownloadRequest_Chunk) XXX_Size() int {
	return xxx_messageInfo_PieceDownloadRequest_Chunk.Size(m)
}
func (m *PieceDownloadRequest_Chunk) XXX_DiscardUnknown() {
	xxx_messageInfo_PieceDownloadRequest_Chunk.DiscardUnknown(m)
}

var xxx_messageInfo_PieceDownloadRequest_Chunk proto.InternalMessageInfo

func (m *PieceDownloadRequest_Chunk) GetOffset() int64 {
	if m != nil {
		return m.Offset
	}
	return 0
}

func (m *PieceDownloadRequest_Chunk) GetChunkSize() int64 {
	if m != nil {
		return m.ChunkSize
	}
	return 0
}

type PieceDownloadResponse struct {
	Chunk                *PieceDownloadResponse_Chunk `protobuf:"bytes,1,opt,name=chunk,proto3" json:"chunk,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *PieceDownloadResponse) Reset()         { *m = PieceDownloadResponse{} }
func (m *PieceDownloadResponse) String() string { return proto.CompactTextString(m) }
func (*PieceDownloadResponse) ProtoMessage()    {}
func (*PieceDownloadResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_23ff32dd550c2439, []int{3}
}
func (m *PieceDownloadResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PieceDownloadResponse.Unmarshal(m, b)
}
func (m *PieceDownloadResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PieceDownloadResponse.Marshal(b, m, deterministic)
}
func (m *PieceDownloadResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PieceDownloadResponse.Merge(m, src)
}
func (m *PieceDownloadResponse) XXX_Size() int {
	return xxx_messageInfo_PieceDownloadResponse.Size(m)
}
func (m *PieceDownloadResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PieceDownloadResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PieceDownloadResponse proto.InternalMessageInfo

func (m *PieceDownloadResponse) GetChunk() *PieceDownloadResponse_Chunk {
	if m != nil {
		return m.Chunk
	}
	return nil
}

// Chunk response for download request
type PieceDownloadResponse_Chunk struct {
	Offset               int64    `protobuf:"varint,1,opt,name=offset,proto3" json:"offset,omitempty"`
	Data                 []byte   `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PieceDownloadResponse_Chunk) Reset()         { *m = PieceDownloadResponse_Chunk{} }
func (m *PieceDownloadResponse_Chunk) String() string { return proto.CompactTextString(m) }
func (*PieceDownloadResponse_Chunk) ProtoMessage()    {}
func (*PieceDownloadResponse_Chunk) Descriptor() ([]byte, []int) {
	return fileDescriptor_23ff32dd550c2439, []int{3, 0}
}
func (m *PieceDownloadResponse_Chunk) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PieceDownloadResponse_Chunk.Unmarshal(m, b)
}
func (m *PieceDownloadResponse_Chunk) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PieceDownloadResponse_Chunk.Marshal(b, m, deterministic)
}
func (m *PieceDownloadResponse_Chunk) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PieceDownloadResponse_Chunk.Merge(m, src)
}
func (m *PieceDownloadResponse_Chunk) XXX_Size() int {
	return xxx_messageInfo_PieceDownloadResponse_Chunk.Size(m)
}
func (m *PieceDownloadResponse_Chunk) XXX_DiscardUnknown() {
	xxx_messageInfo_PieceDownloadResponse_Chunk.DiscardUnknown(m)
}

var xxx_messageInfo_PieceDownloadResponse_Chunk proto.InternalMessageInfo

func (m *PieceDownloadResponse_Chunk) GetOffset() int64 {
	if m != nil {
		return m.Offset
	}
	return 0
}

func (m *PieceDownloadResponse_Chunk) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type PieceDeleteRequest struct {
	Limit                *OrderLimit2 `protobuf:"bytes,1,opt,name=limit,proto3" json:"limit,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *PieceDeleteRequest) Reset()         { *m = PieceDeleteRequest{} }
func (m *PieceDeleteRequest) String() string { return proto.CompactTextString(m) }
func (*PieceDeleteRequest) ProtoMessage()    {}
func (*PieceDeleteRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_23ff32dd550c2439, []int{4}
}
func (m *PieceDeleteRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PieceDeleteRequest.Unmarshal(m, b)
}
func (m *PieceDeleteRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PieceDeleteRequest.Marshal(b, m, deterministic)
}
func (m *PieceDeleteRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PieceDeleteRequest.Merge(m, src)
}
func (m *PieceDeleteRequest) XXX_Size() int {
	return xxx_messageInfo_PieceDeleteRequest.Size(m)
}
func (m *PieceDeleteRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PieceDeleteRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PieceDeleteRequest proto.InternalMessageInfo

func (m *PieceDeleteRequest) GetLimit() *OrderLimit2 {
	if m != nil {
		return m.Limit
	}
	return nil
}

type PieceDeleteResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PieceDeleteResponse) Reset()         { *m = PieceDeleteResponse{} }
func (m *PieceDeleteResponse) String() string { return proto.CompactTextString(m) }
func (*PieceDeleteResponse) ProtoMessage()    {}
func (*PieceDeleteResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_23ff32dd550c2439, []int{5}
}
func (m *PieceDeleteResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PieceDeleteResponse.Unmarshal(m, b)
}
func (m *PieceDeleteResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PieceDeleteResponse.Marshal(b, m, deterministic)
}
func (m *PieceDeleteResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PieceDeleteResponse.Merge(m, src)
}
func (m *PieceDeleteResponse) XXX_Size() int {
	return xxx_messageInfo_PieceDeleteResponse.Size(m)
}
func (m *PieceDeleteResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PieceDeleteResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PieceDeleteResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*PieceUploadRequest)(nil), "piecestore.PieceUploadRequest")
	proto.RegisterType((*PieceUploadRequest_Chunk)(nil), "piecestore.PieceUploadRequest.Chunk")
	proto.RegisterType((*PieceUploadResponse)(nil), "piecestore.PieceUploadResponse")
	proto.RegisterType((*PieceDownloadRequest)(nil), "piecestore.PieceDownloadRequest")
	proto.RegisterType((*PieceDownloadRequest_Chunk)(nil), "piecestore.PieceDownloadRequest.Chunk")
	proto.RegisterType((*PieceDownloadResponse)(nil), "piecestore.PieceDownloadResponse")
	proto.RegisterType((*PieceDownloadResponse_Chunk)(nil), "piecestore.PieceDownloadResponse.Chunk")
	proto.RegisterType((*PieceDeleteRequest)(nil), "piecestore.PieceDeleteRequest")
	proto.RegisterType((*PieceDeleteResponse)(nil), "piecestore.PieceDeleteResponse")
}

func init() { proto.RegisterFile("piecestore2.proto", fileDescriptor_23ff32dd550c2439) }

var fileDescriptor_23ff32dd550c2439 = []byte{
	// 426 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x54, 0x41, 0xcb, 0xd3, 0x40,
	0x10, 0xfd, 0xb6, 0x4d, 0x82, 0x8e, 0x22, 0xba, 0x9f, 0x95, 0x10, 0xb0, 0xd6, 0x20, 0x6d, 0x41,
	0x48, 0x25, 0xbd, 0x89, 0x16, 0xd4, 0x1e, 0x04, 0x15, 0xcb, 0x4a, 0x2f, 0x5e, 0x24, 0x6d, 0x26,
	0x69, 0x30, 0xcd, 0xc6, 0x64, 0x83, 0xd0, 0xab, 0x47, 0x7f, 0xa9, 0xbf, 0x42, 0xc9, 0x6e, 0xda,
	0x92, 0xb6, 0x36, 0x50, 0xf8, 0x6e, 0xd9, 0x99, 0xf7, 0x66, 0xde, 0x7b, 0xbb, 0x04, 0x1e, 0xa4,
	0x11, 0x2e, 0x31, 0x17, 0x3c, 0x43, 0xd7, 0x49, 0x33, 0x2e, 0x38, 0x85, 0x7d, 0xc9, 0x82, 0x90,
	0x87, 0x5c, 0xd5, 0xad, 0x6e, 0xc8, 0x79, 0x18, 0xe3, 0x48, 0x9e, 0x16, 0x45, 0x30, 0xf2, 0x8b,
	0xcc, 0x13, 0x11, 0x4f, 0xaa, 0xfe, 0xbd, 0x35, 0x0a, 0x2f, 0x4a, 0x82, 0x0a, 0x6f, 0xff, 0x6a,
	0x01, 0x9d, 0x95, 0xa3, 0xe6, 0x69, 0xcc, 0x3d, 0x9f, 0xe1, 0x8f, 0x02, 0x73, 0x41, 0x9f, 0x83,
	0x1e, 0x47, 0xeb, 0x48, 0x98, 0xa4, 0x47, 0x86, 0x77, 0xdc, 0x8e, 0xb3, 0xa3, 0x7d, 0xce, 0x7c,
	0xcc, 0x3e, 0x96, 0x3d, 0x97, 0x29, 0x0c, 0xed, 0x83, 0xce, 0xcb, 0xaa, 0xd9, 0x92, 0xe0, 0xfb,
	0x07, 0x60, 0x97, 0xa9, 0x36, 0x7d, 0x09, 0xfa, 0x72, 0x55, 0x24, 0xdf, 0xcd, 0xb6, 0xc4, 0x3d,
	0x73, 0xf6, 0x1e, 0x9c, 0x63, 0x0d, 0xce, 0xbb, 0x12, 0xcb, 0x14, 0x85, 0x0e, 0x40, 0xf3, 0x79,
	0x82, 0xa6, 0x26, 0xa9, 0xd7, 0xfb, 0x15, 0x92, 0xf8, 0xde, 0xcb, 0x57, 0x4c, 0x02, 0xac, 0x31,
	0xe8, 0x92, 0x48, 0x1f, 0x81, 0xc1, 0x83, 0x20, 0x47, 0xe5, 0xa1, 0xcd, 0xaa, 0x13, 0xa5, 0xa0,
	0xf9, 0x9e, 0xf0, 0xa4, 0xd8, 0xbb, 0x4c, 0x7e, 0xdb, 0x13, 0xb8, 0xae, 0x09, 0xc8, 0x53, 0x9e,
	0xe4, 0xb8, 0x5b, 0x4a, 0x1a, 0x96, 0xda, 0x7f, 0x08, 0x3c, 0x94, 0xb5, 0x29, 0xff, 0x99, 0xdc,
	0x78, 0x8e, 0xaf, 0xea, 0x39, 0xf6, 0x8f, 0x72, 0x3c, 0x50, 0x51, 0x4b, 0xd2, 0x9a, 0x34, 0x05,
	0xf4, 0x18, 0x40, 0x22, 0xbf, 0xe5, 0xd1, 0x06, 0xa5, 0x96, 0x36, 0xbb, 0x2d, 0x2b, 0x5f, 0xa2,
	0x0d, 0xda, 0xbf, 0x09, 0x74, 0x0e, 0xb6, 0x54, 0x71, 0xbd, 0xde, 0xea, 0x52, 0x66, 0x07, 0x67,
	0x74, 0x29, 0x46, 0x5d, 0xd8, 0x45, 0x37, 0xf7, 0xa6, 0x7a, 0xbe, 0x53, 0x8c, 0x51, 0xe0, 0x25,
	0xb1, 0xdb, 0x9d, 0xea, 0xf2, 0xb7, 0x23, 0x94, 0x36, 0xf7, 0x2f, 0x01, 0x98, 0xed, 0x0c, 0xd0,
	0x4f, 0x60, 0xa8, 0xd7, 0x41, 0xbb, 0xe7, 0xdf, 0xad, 0xf5, 0xe4, 0xbf, 0x7d, 0x35, 0xd9, 0xbe,
	0x1a, 0x12, 0x3a, 0x87, 0x5b, 0xdb, 0x34, 0x68, 0xaf, 0xe9, 0x02, 0xad, 0xa7, 0x8d, 0x51, 0x96,
	0x43, 0x5f, 0x10, 0xfa, 0x01, 0x0c, 0x65, 0xe3, 0x84, 0xca, 0x5a, 0x44, 0x27, 0x54, 0xd6, 0xfd,
	0xdb, 0x57, 0x6f, 0xb5, 0xaf, 0xad, 0x74, 0xb1, 0x30, 0xe4, 0x8f, 0x62, 0xfc, 0x2f, 0x00, 0x00,
	0xff, 0xff, 0x83, 0x6c, 0xd9, 0xff, 0x85, 0x04, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// PiecestoreClient is the client API for Piecestore service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type PiecestoreClient interface {
	Upload(ctx context.Context, opts ...grpc.CallOption) (Piecestore_UploadClient, error)
	Download(ctx context.Context, opts ...grpc.CallOption) (Piecestore_DownloadClient, error)
	Delete(ctx context.Context, in *PieceDeleteRequest, opts ...grpc.CallOption) (*PieceDeleteResponse, error)
}

type piecestoreClient struct {
	cc *grpc.ClientConn
}

func NewPiecestoreClient(cc *grpc.ClientConn) PiecestoreClient {
	return &piecestoreClient{cc}
}

func (c *piecestoreClient) Upload(ctx context.Context, opts ...grpc.CallOption) (Piecestore_UploadClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Piecestore_serviceDesc.Streams[0], "/piecestore.Piecestore/Upload", opts...)
	if err != nil {
		return nil, err
	}
	x := &piecestoreUploadClient{stream}
	return x, nil
}

type Piecestore_UploadClient interface {
	Send(*PieceUploadRequest) error
	CloseAndRecv() (*PieceUploadResponse, error)
	grpc.ClientStream
}

type piecestoreUploadClient struct {
	grpc.ClientStream
}

func (x *piecestoreUploadClient) Send(m *PieceUploadRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *piecestoreUploadClient) CloseAndRecv() (*PieceUploadResponse, error) {
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	m := new(PieceUploadResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *piecestoreClient) Download(ctx context.Context, opts ...grpc.CallOption) (Piecestore_DownloadClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Piecestore_serviceDesc.Streams[1], "/piecestore.Piecestore/Download", opts...)
	if err != nil {
		return nil, err
	}
	x := &piecestoreDownloadClient{stream}
	return x, nil
}

type Piecestore_DownloadClient interface {
	Send(*PieceDownloadRequest) error
	Recv() (*PieceDownloadResponse, error)
	grpc.ClientStream
}

type piecestoreDownloadClient struct {
	grpc.ClientStream
}

func (x *piecestoreDownloadClient) Send(m *PieceDownloadRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *piecestoreDownloadClient) Recv() (*PieceDownloadResponse, error) {
	m := new(PieceDownloadResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *piecestoreClient) Delete(ctx context.Context, in *PieceDeleteRequest, opts ...grpc.CallOption) (*PieceDeleteResponse, error) {
	out := new(PieceDeleteResponse)
	err := c.cc.Invoke(ctx, "/piecestore.Piecestore/Delete", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PiecestoreServer is the server API for Piecestore service.
type PiecestoreServer interface {
	Upload(Piecestore_UploadServer) error
	Download(Piecestore_DownloadServer) error
	Delete(context.Context, *PieceDeleteRequest) (*PieceDeleteResponse, error)
}

func RegisterPiecestoreServer(s *grpc.Server, srv PiecestoreServer) {
	s.RegisterService(&_Piecestore_serviceDesc, srv)
}

func _Piecestore_Upload_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PiecestoreServer).Upload(&piecestoreUploadServer{stream})
}

type Piecestore_UploadServer interface {
	SendAndClose(*PieceUploadResponse) error
	Recv() (*PieceUploadRequest, error)
	grpc.ServerStream
}

type piecestoreUploadServer struct {
	grpc.ServerStream
}

func (x *piecestoreUploadServer) SendAndClose(m *PieceUploadResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *piecestoreUploadServer) Recv() (*PieceUploadRequest, error) {
	m := new(PieceUploadRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _Piecestore_Download_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(PiecestoreServer).Download(&piecestoreDownloadServer{stream})
}

type Piecestore_DownloadServer interface {
	Send(*PieceDownloadResponse) error
	Recv() (*PieceDownloadRequest, error)
	grpc.ServerStream
}

type piecestoreDownloadServer struct {
	grpc.ServerStream
}

func (x *piecestoreDownloadServer) Send(m *PieceDownloadResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *piecestoreDownloadServer) Recv() (*PieceDownloadRequest, error) {
	m := new(PieceDownloadRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _Piecestore_Delete_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PieceDeleteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PiecestoreServer).Delete(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/piecestore.Piecestore/Delete",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PiecestoreServer).Delete(ctx, req.(*PieceDeleteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Piecestore_serviceDesc = grpc.ServiceDesc{
	ServiceName: "piecestore.Piecestore",
	HandlerType: (*PiecestoreServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Delete",
			Handler:    _Piecestore_Delete_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Upload",
			Handler:       _Piecestore_Upload_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "Download",
			Handler:       _Piecestore_Download_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "piecestore2.proto",
}
