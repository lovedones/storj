// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package identity_test

import (
	"bytes"
	"crypto/x509/pkix"
	"storj.io/storj/storage"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"storj.io/storj/internal/testcontext"
	"storj.io/storj/internal/testidentity"
	"storj.io/storj/internal/testpeertls"
	"storj.io/storj/pkg/identity"
	"storj.io/storj/pkg/peertls"
)

func TestRevocationDB_Get(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	testidentity.RevocationDBsTest(ctx, t, func(t *testing.T, revDB peertls.RevocationDB, db storage.KeyValueStore) {
		// NB: key indices are reversed as compared to chain indices
		keys, chain, err := testpeertls.NewCertChain(2)
		require.NoError(t, err)

		ext, err := peertls.NewRevocationExt(keys[0], chain[peertls.LeafIndex])
		require.NoError(t, err)

		var rev *peertls.Revocation

		{
			t.Log("missing key")
			rev, err = revDB.Get(chain)
			assert.NoError(t, err)
			assert.Nil(t, rev)

			nodeID, err := identity.NodeIDFromKey(chain[peertls.CAIndex].PublicKey)
			require.NoError(t, err)

			err = db.Put(nodeID.Bytes(), ext.Value)
			require.NoError(t, err)
		}

		{
			t.Log("existing key")
			rev, err = revDB.Get(chain)
			assert.NoError(t, err)

			revBytes, err := rev.Marshal()
			assert.NoError(t, err)
			assert.True(t, bytes.Equal(ext.Value, revBytes))
		}
	})
}

func TestRevocationDB_Put_success(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	testidentity.RevocationDBsTest(ctx, t, func(t *testing.T, revDB peertls.RevocationDB, db storage.KeyValueStore) {
		// NB: key indices are reversed as compared to chain indices
		keys, chain, err := testpeertls.NewCertChain(2)
		require.NoError(t, err)

		firstRevocation, err := peertls.NewRevocationExt(keys[0], chain[peertls.LeafIndex])
		require.NoError(t, err)

		time.Sleep(time.Second)
		newerRevocation, err := peertls.NewRevocationExt(keys[0], chain[peertls.LeafIndex])
		assert.NoError(t, err)

		testcases := []struct {
			name string
			ext  pkix.Extension
		}{
			{
				"new key",
				firstRevocation,
			},
			{
				"existing key - newer timestamp",
				newerRevocation,
			},
			// TODO(bryanchriswhite): test empty/garbage cert/timestamp/sig
		}

		for _, testcase := range testcases {
			t.Log(testcase.name)
			require.NotNil(t, testcase.ext)

			err = revDB.Put(chain, testcase.ext)
			require.NoError(t, err)

			nodeID, err := identity.NodeIDFromKey(chain[peertls.CAIndex].PublicKey)
			require.NoError(t, err)

			revBytes, err := db.Get(nodeID.Bytes())
			require.NoError(t, err)

			assert.Equal(t, testcase.ext.Value, []byte(revBytes))
		}
	})
}

func TestRevocationDB_Put_error(t *testing.T) {
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	testidentity.RevocationDBsTest(ctx, t, func(t *testing.T, revDB peertls.RevocationDB, db storage.KeyValueStore) {
		// NB: key indices are reversed as compared to chain indices
		keys, chain, err := testpeertls.NewCertChain(2)
		require.NoError(t, err)

		olderRevocation, err := peertls.NewRevocationExt(keys[0], chain[peertls.LeafIndex])
		assert.NoError(t, err)

		time.Sleep(time.Second)
		newerRevocation, err := peertls.NewRevocationExt(keys[0], chain[peertls.LeafIndex])
		require.NoError(t, err)

		err = revDB.Put(chain, newerRevocation)
		require.NoError(t, err)

		testcases := []struct {
			name string
			ext  pkix.Extension
			err  error
		}{
			{
				"existing key - older timestamp",
				olderRevocation,
				peertls.ErrRevocationTimestamp,
			},
			// TODO(bryanchriswhite): test empty/garbage cert/timestamp/sig
		}

		for _, testcase := range testcases {
			t.Log(testcase.name)
			require.NotNil(t, testcase.ext)

			err = revDB.Put(chain, testcase.ext)
			assert.True(t, peertls.ErrExtension.Has(err))
			assert.Equal(t, testcase.err, err)
		}
	})
}
