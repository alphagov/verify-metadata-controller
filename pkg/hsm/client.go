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

type CloudHSMToolResponse struct {
	Certificate 				string `json:"certificate"`
	CertificateSigningRequest	string `json:"csr"`
}

type Client interface {
	CreateRSAKeyPair(label string, hsmCreds Credentials) (response hsm.CloudHSMToolResponse, err error)
	FindOrCreateRSAKeyPair(label string, hsmCreds Credentials) (response hsm.CloudHSMToolResponse, err error)
	GenerateAndSignMetadata(metadataSigningCert []byte, metadataSigningKeyLabel string, spec verifyv1beta1.MetadataSpec, hsmCreds Credentials) (signedMetadata []byte, err error)
}
