package peertls_test

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"

	"storj.io/storj/internal/testpeertls"
	"storj.io/storj/pkg/peertls"
	"storj.io/storj/pkg/pkcrypto"
)

func RevokeLeaf(keys []crypto.PrivateKey, chain []*x509.Certificate) ([]*x509.Certificate, pkix.Extension, error) {
	var revocation pkix.Extension
	revokingKey, err := pkcrypto.GeneratePrivateKey()
	if err != nil {
		return nil, revocation, err
	}

	revokingTemplate, err := peertls.LeafTemplate()
	if err != nil {
		return nil, revocation, err
	}

	revokingCert, err := peertls.NewCert(revokingKey, keys[0], revokingTemplate, chain[peertls.CAIndex])
	if err != nil {
		return nil, revocation, err
	}

	err = peertls.AddRevocationExt(keys[0], chain[peertls.LeafIndex], revokingCert)
	if err != nil {
		return nil, revocation, err
	}

	revocation = revokingCert.ExtraExtensions[0]
	return append([]*x509.Certificate{revokingCert}, chain[peertls.CAIndex:]...), revocation, nil
}

func RevokeCA(keys []crypto.PrivateKey, chain []*x509.Certificate) ([]*x509.Certificate, pkix.Extension, error) {
	caCert := chain[peertls.CAIndex]
	err := peertls.AddRevocationExt(keys[0], caCert, caCert)
	if err != nil {
		return nil, pkix.Extension{}, err
	}

	return append([]*x509.Certificate{caCert}, chain[peertls.CAIndex:]...), caCert.ExtraExtensions[0], nil
}

func NewRevokedLeafChain() ([]crypto.PrivateKey, []*x509.Certificate, pkix.Extension, error) {
	keys, certs, err := testpeertls.NewCertChain(2)
	if err != nil {
		return nil, nil, pkix.Extension{}, err
	}

	newChain, revocation, err := RevokeLeaf(keys, certs)
	return keys, newChain, revocation, err
}
