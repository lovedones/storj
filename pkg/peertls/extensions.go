// Copyright (C) 2019 Storj Labs, Inc.
// See LICENSE for copying information.

package peertls

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/zeebo/errs"

	"storj.io/storj/pkg/pkcrypto"
)

const (
	//SignedCertExtID = iota
	//RevocationExtID
	// RevocationBucket is the bolt bucket to store revocation data in
	RevocationBucket = "revocations"
)

const (
	// LeafIndex is the index of the leaf certificate in a cert chain (0)
	LeafIndex = iota
	// CAIndex is the index of the CA certificate in a cert chain (1)
	CAIndex
)

var (
	AvailableExtensionHandlers = &ExtensionHandlers{
		handlers: []ExtensionHandler{},
	}

	// NB: 2.999.X is reserved for "example" OIDs
	// (see http://oid-info.com/get/2.999)
	// 2.999.1.X -- storj general/misc. extensions

	// SignedCertExtID is the asn1 object ID for a pkix extensionHandler holding a
	// signature of the cert it's extending, signed by some CA (e.g. the root cert chain).
	// This extensionHandler allows for an additional signature per certificate.
	SignedCertExtID = asn1.ObjectIdentifier{2, 999, 1, 1}
	// RevocationExtID is the asn1 object ID for a pkix extensionHandler containing the
	// most recent certificate revocation data
	// for the current TLS cert chain.
	RevocationExtID = asn1.ObjectIdentifier{2, 999, 1, 2}

	CAWhitelistSignedLeafExtensionHandler = &GenericExtensionHandler{
		oid:         &SignedCertExtID,
		newVerifier: caWhitelistSignedLeafVerifier,
	}

	// ErrExtension is used when an error occurs while processing an extensionHandler.
	ErrExtension = errs.Class("extension error")

	// ErrUniqueExtensions is used when multiple extensions have the same Id
	ErrUniqueExtensions = ErrExtension.New("extensions are not unique")

)

// TLSExtConfig is used to bind cli flags for determining which extensions will
// be used by the server
type TLSExtConfig struct {
	Revocation          bool   `default:"true" help:"if true, client leaves may contain the most recent certificate revocation for the current certificate"`
	WhitelistSignedLeaf bool   `default:"false" help:"if true, client leaves must contain a valid \"signed certificate extension\" (NB: verified against certs in the peer ca whitelist; i.e. if true, a whitelist must be provided)"`
}

// ExtensionOptions holds options for use in handling extensions
type ExtensionOptions struct {
	PeerCAWhitelist []*x509.Certificate
	RevDB           RevocationDB
}

// ExtensionHandlers is a collection of `extensionHandler`s for convenience (see `VerifyFunc`)
type ExtensionHandlers struct {
	handlers []ExtensionHandler
}

type ExtensionVerificationFunc func(pkix.Extension, [][]*x509.Certificate) error

// ExtensionHandler represents a verify function for handling an extension
// with the given ID
type ExtensionHandler interface {
	OID() *asn1.ObjectIdentifier
	NewVerifier(options ExtensionOptions) ExtensionVerificationFunc
}

type GenericExtensionHandler struct {
	oid         *asn1.ObjectIdentifier
	newVerifier func(options ExtensionOptions) ExtensionVerificationFunc
}

func init() {
	AvailableExtensionHandlers.Register(
		CAWhitelistSignedLeafExtensionHandler,
		RevocationCheckExtensionHandler,
		RevocationUpdateExtensionHandler,
	)
}

// AddSignedCertExt generates a signed certificate extension for a cert and attaches
// it to that cert.
func AddSignedCertExt(key crypto.PrivateKey, cert *x509.Certificate) error {
	signature, err := pkcrypto.HashAndSign(key, cert.RawTBSCertificate)
	if err != nil {
		return err
	}

	err = AddExtension(cert, pkix.Extension{
		Id:    SignedCertExtID,
		Value: signature,
	})
	if err != nil {
		return err
	}
	return nil
}

// AddExtension adds one or more extensions to a certificate
func AddExtension(cert *x509.Certificate, exts ...pkix.Extension) (err error) {
	if len(exts) == 0 {
		return nil
	}
	if !uniqueExts(append(cert.ExtraExtensions, exts...)) {
		return ErrUniqueExtensions
	}

	for _, ext := range exts {
		e := pkix.Extension{Id: ext.Id, Value: make([]byte, len(ext.Value))}
		copy(e.Value, ext.Value)
		cert.ExtraExtensions = append(cert.ExtraExtensions, e)
	}
	return nil
}

// Register adds an extension handler to the list of extension handlers.
func (extHandlers *ExtensionHandlers) Register(handlers ...ExtensionHandler) {
	extHandlers.handlers = append(extHandlers.handlers, handlers...)
}

// VerifyFunc returns a peer certificate verification function which iterates
// over all the leaf cert's extensions and receiver extensions and calls
// `extensionHandler#verify` when it finds a match by id (`asn1.ObjectIdentifier`).
func (extHandlers ExtensionHandlers) VerifyFunc(opts ExtensionOptions) PeerCertVerificationFunc {
	if len(extHandlers.handlers) == 0 {
		return nil
	}

	verifiers := make(map[*asn1.ObjectIdentifier]ExtensionVerificationFunc)
	for _, handler := range extHandlers.handlers {
		verifiers[handler.OID()] = handler.NewVerifier(opts)
	}

	return func(_ [][]byte, parsedChains [][]*x509.Certificate) error {
		for _, cert := range parsedChains[0] {
			exts := make(map[string]pkix.Extension)
			for _, ext := range cert.ExtraExtensions {
				exts[ext.Id.String()] = ext
			}

			for oid, verify := range verifiers {
				if ext, ok := exts[oid.String()]; ok {
					err := verify(ext, parsedChains)
					if err != nil {
						return ErrExtension.Wrap(err)
					}
				}
			}
		}
		return nil
	}
}

func (geh *GenericExtensionHandler) OID() *asn1.ObjectIdentifier {
	return geh.oid
}

func (geh *GenericExtensionHandler) NewVerifier(opts ExtensionOptions) ExtensionVerificationFunc {
	return geh.newVerifier(opts)
}

func caWhitelistSignedLeafVerifier(opts ExtensionOptions) ExtensionVerificationFunc {
	return func(ext pkix.Extension, chains [][]*x509.Certificate) error {
		if opts.PeerCAWhitelist == nil {
			return ErrVerifyCAWhitelist.New("no whitelist provided")
		}

		leaf := chains[0][LeafIndex]
		for _, ca := range opts.PeerCAWhitelist {
			err := pkcrypto.HashAndVerifySignature(ca.PublicKey, leaf.RawTBSCertificate, ext.Value)
			if err == nil {
				return nil
			}
		}
		return ErrVerifyCAWhitelist.New("leaf extension")
	}
}

