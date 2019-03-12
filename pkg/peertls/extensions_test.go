// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package peertls_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zeebo/errs"

	"storj.io/storj/internal/testcontext"
	"storj.io/storj/internal/testpeertls"
	"storj.io/storj/pkg/identity"
	"storj.io/storj/pkg/peertls"
)

func TestParseExtensions(t *testing.T) {
	// TODO: separate this into multiple tests!
	ctx := testcontext.New(t)
	defer ctx.Cleanup()

	revokedLeafKeys, revokedLeafChain, _, err := NewRevokedLeafChain()
	assert.NoError(t, err)

	whitelistSignedKeys, whitelistSignedChain, err := testpeertls.NewCertChain(3)
	assert.NoError(t, err)

	err = peertls.AddSignedCertExt(whitelistSignedKeys[0], whitelistSignedChain[0])
	assert.NoError(t, err)

	_, unrelatedChain, err := testpeertls.NewCertChain(1)
	assert.NoError(t, err)

	revDB, err := identity.NewRevocationDBBolt(ctx.File("revocations.db"))
	assert.NoError(t, err)
	defer ctx.Check(revDB.Close)

	cases := []struct {
		testID    string
		config    peertls.TLSExtConfig
		extLen    int
		certChain []*x509.Certificate
		whitelist []*x509.Certificate
		errClass  *errs.Class
		err       error
	}{
		{
			"leaf whitelist signature - success",
			peertls.TLSExtConfig{WhitelistSignedLeaf: true},
			1,
			whitelistSignedChain,
			[]*x509.Certificate{whitelistSignedChain[2]},
			nil,
			nil,
		},
		{
			"leaf whitelist signature - failure (empty whitelist)",
			peertls.TLSExtConfig{WhitelistSignedLeaf: true},
			1,
			whitelistSignedChain,
			nil,
			&peertls.ErrVerifyCAWhitelist,
			nil,
		},
		{
			"leaf whitelist signature - failure",
			peertls.TLSExtConfig{WhitelistSignedLeaf: true},
			1,
			whitelistSignedChain,
			unrelatedChain,
			&peertls.ErrVerifyCAWhitelist,
			nil,
		},
		{
			"certificate revocation - single revocation ",
			peertls.TLSExtConfig{Revocation: true},
			1,
			revokedLeafChain,
			nil,
			nil,
			nil,
		},
		{
			"certificate revocation - serial revocations",
			peertls.TLSExtConfig{Revocation: true},
			1,
			func() []*x509.Certificate {
				rev := new(peertls.Revocation)
				time.Sleep(1 * time.Second)
				chain, revocationExt, err := RevokeLeaf(revokedLeafKeys, revokedLeafChain)
				assert.NoError(t, err)

				err = rev.Unmarshal(revocationExt.Value)
				assert.NoError(t, err)

				return chain
			}(),
			nil,
			nil,
			nil,
		},
		{
			"certificate revocation - serial revocations error (older timestamp)",
			peertls.TLSExtConfig{Revocation: true},
			1,
			func() []*x509.Certificate {
				keys, chain, _, err := NewRevokedLeafChain()
				assert.NoError(t, err)

				rev := new(peertls.Revocation)
				err = rev.Unmarshal(chain[0].ExtraExtensions[0].Value)
				assert.NoError(t, err)

				rev.Timestamp = rev.Timestamp + 300
				err = rev.Sign(keys[0])
				assert.NoError(t, err)

				revBytes, err := rev.Marshal()
				assert.NoError(t, err)

				err = revDB.Put(chain, pkix.Extension{
					Id:    peertls.RevocationExtID,
					Value: revBytes,
				})
				assert.NoError(t, err)
				return chain
			}(),
			nil,
			&peertls.ErrExtension,
			peertls.ErrRevocationTimestamp,
		},
		{
			"certificate revocation and leaf whitelist signature",
			peertls.TLSExtConfig{Revocation: true, WhitelistSignedLeaf: true},
			2,
			func() []*x509.Certificate {
				_, chain, _, err := NewRevokedLeafChain()
				assert.NoError(t, err)

				err = peertls.AddSignedCertExt(whitelistSignedKeys[0], chain[0])
				assert.NoError(t, err)

				return chain
			}(),
			[]*x509.Certificate{whitelistSignedChain[2]},
			nil,
			nil,
		},
	}

	for _, c := range cases {
		t.Run(c.testID, func(t *testing.T) {
			opts := peertls.ExtensionOptions{
				PeerCAWhitelist: c.whitelist,
				RevDB:           revDB,
			}

			//assert.Equal(t, c.extLen, len(handlers))
			err := peertls.AvailableExtensionHandlers.VerifyFunc(opts)(nil, [][]*x509.Certificate{c.certChain})
			if c.errClass != nil {
				assert.True(t, c.errClass.Has(err))
			}
			if c.err != nil {
				assert.NotNil(t, err)
			}
			if c.errClass == nil && c.err == nil {
				assert.NoError(t, err)
			}
		})
	}
}
