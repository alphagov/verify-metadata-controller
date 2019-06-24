package hsm

import (
	verifyv1beta1 "github.com/alphagov/verify-metadata-controller/pkg/apis/verify/v1beta1"
)

type Credentials struct {
	IP         string
	User       string
	Password   string
	CustomerCA string
}

type Client interface {
	CreateRSAKeyPair(label string, hsmCreds Credentials) (publicCert []byte, err error)
	FindOrCreateRSAKeyPair(label string, hsmCreds Credentials) (signingCert []byte, err error)
	GenerateAndSignMetadata(metadataSigningCert []byte, metadataSigningKeyLabel string, spec verifyv1beta1.MetadataSpec, hsmCreds Credentials) (signedMetadata []byte, err error)
	CreateSelfSignedCert(label string, hsmCreds Credentials, req CertRequest) ([]byte, error)
	CreateChainedCert(label string, hsmCreds Credentials, req CertRequest) ([]byte, error)
}
