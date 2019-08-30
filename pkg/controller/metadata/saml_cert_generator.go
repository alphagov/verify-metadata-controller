package metadata

import "github.com/alphagov/verify-metadata-controller/pkg/hsm"

type SamlCertGenerator struct {
	signingCert        []byte
	encryptionCert     []byte
	signingCredentials hsm.Credentials
}
