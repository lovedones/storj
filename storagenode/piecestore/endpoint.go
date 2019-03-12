// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package piecestore

import (
	"context"
	"io"
	"time"

	"github.com/zeebo/errs"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	monkit "gopkg.in/spacemonkeygo/monkit.v2"

	"storj.io/storj/internal/memory"
	"storj.io/storj/internal/sync2"
	"storj.io/storj/pkg/auth/signing"
	"storj.io/storj/pkg/identity"
	"storj.io/storj/pkg/pb"
	"storj.io/storj/pkg/storj"
	"storj.io/storj/storagenode/orders"
	"storj.io/storj/storagenode/pieces"
	"storj.io/storj/storagenode/trust"
)

var (
	mon = monkit.Package()

	Error       = errs.Class("piecestore error")
	ErrProtocol = errs.Class("piecestore protocol error")
	ErrInternal = errs.Class("piecestore internal error")
)

// TODO: avoid protobuf definitions in interfaces

type PieceMeta interface {
	Add(ctx context.Context, limit *pb.OrderLimit2, hash *pb.PieceHash) error
	Delete(ctx context.Context, satellite storj.NodeID, pieceID storj.PieceID2) error
	// Iteration for collector
}

type discardMeta struct{}

func (discardMeta) Add(ctx context.Context, limit *pb.OrderLimit2, hash *pb.PieceHash) error {
	return nil
}
func (discardMeta) Delete(ctx context.Context, satellite storj.NodeID, pieceID storj.PieceID2) error {
	return nil
}

type discardOrders struct{}

func (discardOrders) Add(ctx context.Context, limit *pb.OrderLimit2, order *pb.Order2) error {
	return nil
}

// TODO: should the reader, writer have context for read/write?

var _ pb.PiecestoreServer = (*Endpoint)(nil)

type Config struct {
	ExpirationGracePeriod time.Duration `help:"how soon before expiration date should things be considered expired" default:"48h0m0s"`
}

type Endpoint struct {
	log *zap.Logger

	config Config

	signer        signing.Signer
	trust         *trust.Pool
	activeSerials *SerialNumbers

	store *pieces.Store

	pieceMeta PieceMeta // todo should this be folded into pieces.Store instead?
	orders    orders.Table
}

func NewEndpoint(log *zap.Logger, signer signing.Signer, trust *trust.Pool, store *pieces.Store, pieceMeta PieceMeta, orders orders.Table, config Config) (*Endpoint, error) {
	activeSerials, err := LoadSerialNumbers(pieceMeta)
	if err != nil {
		return nil, err
	}

	return &Endpoint{
		log:           log,
		config:        config,
		signer:        signer,
		trust:         trust,
		activeSerials: activeSerials,
		store:         store,
		pieceMeta:     discardMeta{},
		orders:        discardOrders{},
	}, nil
}

func (endpoint *Endpoint) Delete(ctx context.Context, delete *pb.PieceDeleteRequest) (_ *pb.PieceDeleteResponse, err error) {
	defer mon.Task()(&ctx)(&err)

	if delete.Limit.Action != pb.Action_DELETE {
		return nil, Error.New("expected delete action got %v", delete.Limit.Action) // TODO: report grpc status unauthorized or bad request
	}

	if err := endpoint.VerifyOrderLimit(ctx, delete.Limit); err != nil {
		// TODO: report grpc status unauthorized or bad request
		return nil, Error.Wrap(err)
	}

	// TODO: parallelize this and maybe return early
	pieceInfoErr := endpoint.pieceMeta.Delete(ctx, delete.Limit.SatelliteId, delete.Limit.PieceId)
	pieceErr := endpoint.store.Delete(ctx, delete.Limit.SatelliteId, delete.Limit.PieceId)

	if err := errs.Combine(pieceInfoErr, pieceErr); err != nil {
		// explicitly ignoring error because the errors
		// TODO: add more debug info
		endpoint.log.Error("unable to delete", zap.Error(err))
		// TODO: report internal server internal or missing error using grpc status,
		// e.g. missing might happen when we get a deletion request after garbage collection has deleted it
	}

	return &pb.PieceDeleteResponse{}, nil
}

func (endpoint *Endpoint) Upload(stream pb.Piecestore_UploadServer) (err error) {
	ctx := stream.Context()
	defer mon.Task()(&ctx)(&err)

	// TODO: set connection timeouts
	// TODO: set maximum message size

	var message *pb.PieceUploadRequest

	message, err = stream.Recv()
	switch {
	case err != nil:
		return ErrProtocol.Wrap(err)
	case message == nil:
		return ErrProtocol.New("expected a message")
	case message.Limit == nil:
		return ErrProtocol.New("expected order limit as the first message")
	}
	limit := message.Limit

	// TODO: verify that we have have expected amount of storage before continuing

	if limit.Action != pb.Action_PUT && limit.Action != pb.Action_PUT_REPAIR {
		return ErrProtocol.New("expected put or put repair action got %v", limit.Action) // TODO: report grpc status unauthorized or bad request
	}

	if err := endpoint.VerifyOrderLimit(ctx, limit); err != nil {
		return err // TODO: report grpc status unauthorized or bad request
	}

	peer, err := identity.PeerIdentityFromContext(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	pieceWriter, err := endpoint.store.Writer(ctx, limit.SatelliteId, limit.PieceId)
	if err != nil {
		return ErrInternal.Wrap(err) // TODO: report grpc status internal server error
	}
	defer pieceWriter.Cancel() // similarly how transcation Rollback works

	largestOrder := &pb.Order2{}
	defer endpoint.SaveOrder(ctx, limit, largestOrder)

	for {
		message, err = stream.Recv() // TODO: reuse messages to avoid allocations
		if err == io.EOF {
			return ErrProtocol.New("unexpected EOF")
		} else if err != nil {
			return ErrProtocol.Wrap(err) // TODO: report grpc status bad message
		}
		if message == nil {
			return ErrProtocol.New("expected a message") // TODO: report grpc status bad message
		}

		switch {
		default:
			return ErrProtocol.New("message didn't contain any of order, chunk or done") // TODO: report grpc status bad message

		case message.Order != nil:
			if err := endpoint.VerifyOrder(ctx, peer, limit, message.Order, largestOrder.Amount); err != nil {
				return err
			}
			largestOrder = message.Order

		case message.Chunk != nil:
			if message.Chunk.Offset != pieceWriter.Size() {
				return ErrProtocol.New("chunk out of order") // TODO: report grpc status bad message
			}

			if largestOrder.Amount < pieceWriter.Size()+int64(len(message.Chunk.Data)) {
				// TODO: should we write currently and give a chance for uplink to remedy the situation?
				return ErrProtocol.New("not enough allocated, allocated=%v writing=%v", largestOrder.Amount, pieceWriter.Size()+int64(len(message.Chunk.Data))) // TODO: report grpc status ?
			}

			if _, err := pieceWriter.Write(message.Chunk.Data); err != nil {
				return ErrInternal.Wrap(err) // TODO: report grpc status internal server error
			}

		case message.Done != nil:
			expectedHash := pieceWriter.Hash()
			if err := endpoint.VerifyPieceHash(ctx, peer, limit, message.Done, expectedHash); err != nil {
				return err // TODO: report grpc status internal server error
			}

			if err := pieceWriter.Commit(); err != nil {
				return ErrInternal.Wrap(err) // TODO: report grpc status internal server error
			}

			// TODO: do this in a goroutine
			{
				if err := endpoint.pieceMeta.Add(ctx, limit, message.Done); err != nil {
					return ErrInternal.Wrap(err)
				}
			}

			storageNodeHash, err := signing.SignPieceHash(endpoint.signer, &pb.PieceHash{
				PieceId: limit.PieceId,
				Hash:    expectedHash,
			})
			if err != nil {
				return ErrInternal.Wrap(err)
			}

			closeErr := stream.SendAndClose(&pb.PieceUploadResponse{
				Done: storageNodeHash,
			})
			return ErrProtocol.Wrap(ignoreEOF(closeErr))
		}
	}
}

func (endpoint *Endpoint) Download(stream pb.Piecestore_DownloadServer) (err error) {
	ctx := stream.Context()
	defer mon.Task()(&ctx)(&err)

	// TODO: set connection timeouts
	// TODO: set maximum message size

	var message *pb.PieceDownloadRequest

	// receive limit and chunk from uplink
	message, err = stream.Recv()
	if err != nil {
		return ErrProtocol.Wrap(err)
	}
	if message.Limit == nil || message.Chunk == nil {
		return ErrProtocol.New("expected order limit and chunk as the first message")
	}
	limit, chunk := message.Limit, message.Chunk

	if limit.Action != pb.Action_GET && limit.Action != pb.Action_GET_REPAIR && limit.Action != pb.Action_GET_AUDIT {
		return ErrProtocol.New("expected get or get repair or audit action got %v", limit.Action) // TODO: report grpc status unauthorized or bad request
	}

	if chunk.ChunkSize > limit.Limit {
		return ErrProtocol.New("requested more that order limit allows, limit=%v requested=%v", limit.Limit, chunk.ChunkSize)
	}

	if err := endpoint.VerifyOrderLimit(ctx, limit); err != nil {
		return Error.Wrap(err) // TODO: report grpc status unauthorized or bad request
	}

	peer, err := identity.PeerIdentityFromContext(ctx)
	if err != nil {
		return Error.Wrap(err)
	}

	pieceReader, err := endpoint.store.Reader(ctx, limit.SatelliteId, limit.PieceId)
	if err != nil {
		return ErrInternal.Wrap(err) // TODO: report grpc status internal server error
	}
	defer func() {
		err := pieceReader.Close() // similarly how transcation Rollback works
		if err != nil {
			// no reason to report this error to the uplink
			endpoint.log.Error("failed to close piece reader", zap.Error(err))
		}
	}()

	// TODO: verify chunk.Size behavior logic with regards to reading all
	if chunk.Offset+chunk.ChunkSize > pieceReader.Size() {
		return Error.New("requested more data than available, requesting=%v available=%v", chunk.Offset+chunk.ChunkSize, pieceReader.Size())
	}

	throttle := sync2.NewThrottle()
	// TODO: see whether this can be implemented without a goroutine

	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() (err error) {
		var maximumChunkSize = 1 * memory.MiB.Int64()

		currentOffset := chunk.Offset
		unsentAmount := chunk.ChunkSize
		for unsentAmount > 0 {
			tryToSend := min(unsentAmount, maximumChunkSize)

			// TODO: add timeout here
			chunkSize, err := throttle.ConsumeOrWait(tryToSend)
			if err != nil {
				// this can happen only because uplink decided to close the connection
				return nil
			}

			chunkData := make([]byte, chunkSize)
			_, err = pieceReader.Seek(currentOffset, io.SeekStart)
			if err != nil {
				return ErrInternal.Wrap(err)
			}

			_, err = pieceReader.Read(chunkData)
			if err != nil {
				return ErrInternal.Wrap(err)
			}

			err = stream.Send(&pb.PieceDownloadResponse{
				Chunk: &pb.PieceDownloadResponse_Chunk{
					Offset: currentOffset,
					Data:   chunkData,
				},
			})
			if err != nil {
				// err is io.EOF when uplink asked for a piece, but decided not to retrieve it,
				// no need to propagate it
				return ErrProtocol.Wrap(ignoreEOF(err))
			}

			currentOffset += chunkSize
			unsentAmount -= chunkSize
		}

		return nil
	})

	recvErr := func() (err error) {
		largestOrder := &pb.Order2{}
		defer endpoint.SaveOrder(ctx, limit, largestOrder)

		// ensure that we always terminate sending goroutine
		defer throttle.Fail(io.EOF)

		for {
			// TODO: check errors
			// TODO: add timeout here
			message, err = stream.Recv()
			if err != nil {
				// err is io.EOF when uplink closed the connection, no need to return error
				return ErrProtocol.Wrap(ignoreEOF(err))
			}

			if message == nil || message.Order == nil {
				return ErrProtocol.New("expected order as the message")
			}

			if err := endpoint.VerifyOrder(ctx, peer, limit, message.Order, largestOrder.Amount); err != nil {
				return err
			}
			if err := throttle.Produce(message.Order.Amount - largestOrder.Amount); err != nil {
				// shouldn't happen since only receiving side is calling Fail
				return ErrInternal.Wrap(err)
			}
			largestOrder = message.Order
		}
	}()

	// ensure we wait for sender to complete
	sendErr := group.Wait()
	return Error.Wrap(errs.Combine(sendErr, recvErr))
}

func (endpoint *Endpoint) SaveOrder(ctx context.Context, limit *pb.OrderLimit2, order *pb.Order2) {
	// TODO: do this in a goroutine
	if order == nil || order.Amount <= 0 {
		return
	}
	err := endpoint.orders.Add(ctx, limit, order)
	if err != nil {
		endpoint.log.Error("failed to add order", zap.Error(err))
	}
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func ignoreEOF(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}