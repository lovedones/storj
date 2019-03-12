package testidentity

import (
	"storj.io/storj/storage"
	"testing"

	"github.com/alicebob/miniredis"
	"github.com/stretchr/testify/require"

	"storj.io/storj/internal/testcontext"
	"storj.io/storj/pkg/identity"
	"storj.io/storj/pkg/peertls"
)

func RevocationDBsTest(ctx *testcontext.Context, t *testing.T, test func(*testing.T, peertls.RevocationDB, storage.KeyValueStore)) {
	revocationDBPath := ctx.File("revocations.db")

	t.Run("Redis-backed revocation DB", func(t *testing.T) {
		redisServer, err := miniredis.Run()
		require.NoError(t, err)

		{
			// Test using redis-backed revocation DB
			dbURL := "redis://" + redisServer.Addr() + "?db=0"
			redisRevDB, err := identity.NewRevDB(dbURL)
			require.NoError(t, err)

			test(t, redisRevDB, redisRevDB.DB)
			ctx.Check(redisRevDB.Close)
		}

		redisServer.Close()
	})

	t.Run("Bolt-backed revocation DB", func(t *testing.T) {
		{
			// Test using bolt-backed revocation DB
			dbURL := "bolt://" + revocationDBPath
			boltRevDB, err := identity.NewRevDB(dbURL)
			require.NoError(t, err)

			test(t, boltRevDB, boltRevDB.DB)
			ctx.Check(boltRevDB.Close)
		}
	})
}
