// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package metainfo

import (
	"context"

	"google.golang.org/grpc"
	monkit "gopkg.in/spacemonkeygo/monkit.v2"

	"storj.io/storj/pkg/auth/grpcauth"
	"storj.io/storj/pkg/pb"
	"storj.io/storj/pkg/storj"
	"storj.io/storj/pkg/transport"
)

var (
	mon = monkit.Package()
)

// Metainfo creates a grpcClient
type Metainfo struct {
	client pb.MetainfoClient
}

// New used as a public function
func New(gcclient pb.MetainfoClient) (metainfo *Metainfo) {
	return &Metainfo{client: gcclient}
}

// a compiler trick to make sure *Metainfo implements Client
var _ Client = (*Metainfo)(nil)

// ListItem is a single item in a listing
type ListItem struct {
	Path     storj.Path
	Pointer  *pb.Pointer
	IsPrefix bool
}

// Client interface for the Metainfo service
type Client interface {
	CreateSegment(ctx context.Context, bucket string, path storj.Path, totalNodes int32, maxSegmentSize int64) ([]*pb.AddressedOrderLimit, error)
	CommitSegment(ctx context.Context, bucket string, path storj.Path, segmentIndex int64, pointer *pb.Pointer) error
	ReadSegment(ctx context.Context, bucket string, path storj.Path, segmentIndex int64) (*pb.Pointer, []*pb.AddressedOrderLimit, error)
	DeleteSegment(ctx context.Context, bucket string, path storj.Path, segmentIndex int64) ([]*pb.AddressedOrderLimit, error)
	ListSegments(ctx context.Context, bucket string, prefix, startAfter, endBefore storj.Path, recursive bool, limit int32, metaFlags uint32) (items []ListItem, more bool, err error)
}

// NewClient initializes a new metainfo client
func NewClient(ctx context.Context, tc transport.Client, address string, APIKey string) (*Metainfo, error) {
	apiKeyInjector := grpcauth.NewAPIKeyInjector(APIKey)
	conn, err := tc.DialAddress(
		ctx,
		address,
		grpc.WithUnaryInterceptor(apiKeyInjector),
	)
	if err != nil {
		return nil, err
	}

	return &Metainfo{client: pb.NewMetainfoClient(conn)}, nil
}

// CreateSegment requests the order limits for creating a new segment
func (metainfo *Metainfo) CreateSegment(ctx context.Context, bucket string, path storj.Path, totalNodes int32, maxSegmentSize int64) (limits []*pb.AddressedOrderLimit, err error) {
	defer mon.Task()(&ctx)(&err)

	response, err := metainfo.client.CreateSegment(ctx, &pb.SegmentWriteRequest{
		Bucket:         []byte(bucket),
		Path:           []byte(path),
		TotalNodes:     totalNodes,
		MaxSegmentSize: maxSegmentSize,
	})

	return response.GetAddressedLimits(), err
}

// CommitSegment requests to store the pointer for the segment
func (metainfo *Metainfo) CommitSegment(ctx context.Context, bucket string, path storj.Path, segmentIndex int64, pointer *pb.Pointer) (err error) {
	defer mon.Task()(&ctx)(&err)

	_, err = metainfo.client.CommitSegment(ctx, &pb.SegmentCommitRequest{
		Bucket:  []byte(bucket),
		Path:    []byte(path),
		Segment: segmentIndex,
		Pointer: pointer,
	})

	return err
}

// ReadSegment requests the order limits for reading a segment
func (metainfo *Metainfo) ReadSegment(ctx context.Context, bucket string, path storj.Path, segmentIndex int64) (pointer *pb.Pointer, limits []*pb.AddressedOrderLimit, err error) {
	defer mon.Task()(&ctx)(&err)

	response, err := metainfo.client.DownloadSegment(ctx, &pb.SegmentDownloadRequest{
		Bucket:  []byte(bucket),
		Path:    []byte(path),
		Segment: segmentIndex,
	})

	return response.GetPointer(), response.GetAddressedLimits(), err
}

// DeleteSegment requests the order limits for deleting a segment
func (metainfo *Metainfo) DeleteSegment(ctx context.Context, bucket string, path storj.Path, segmentIndex int64) (limits []*pb.AddressedOrderLimit, err error) {
	defer mon.Task()(&ctx)(&err)

	response, err := metainfo.client.DeleteSegment(ctx, &pb.SegmentDeleteRequest{
		Bucket:  []byte(bucket),
		Path:    []byte(path),
		Segment: segmentIndex,
	})

	return response.GetAddressedLimits(), err
}

// ListSegments lists the available segments
func (metainfo *Metainfo) ListSegments(ctx context.Context, bucket string, prefix, startAfter, endBefore storj.Path, recursive bool, limit int32, metaFlags uint32) (items []ListItem, more bool, err error) {
	defer mon.Task()(&ctx)(&err)

	response, err := metainfo.client.ListSegments(ctx, &pb.ListSegmentsRequest{
		Bucket:     []byte(bucket),
		Prefix:     []byte(prefix),
		StartAfter: []byte(startAfter),
		EndBefore:  []byte(endBefore),
		Recursive:  recursive,
		Limit:      limit,
		MetaFlags:  metaFlags,
	})

	list := response.GetItems()
	items = make([]ListItem, len(list))
	for i, item := range list {
		items[i] = ListItem{
			Path:     storj.Path(item.GetPath()),
			Pointer:  item.GetPointer(),
			IsPrefix: item.IsPrefix,
		}
	}

	return items, response.GetMore(), err
}