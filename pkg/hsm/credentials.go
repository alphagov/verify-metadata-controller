package hsm

import (
	"fmt"
	"io/ioutil"
	"os"
)

const (
	cloudHSMKeyType           = "cloudhsm"
	metadataXMLKey            = "metadata.xml"
	truststorePassword        = "mashmallow"
	DefaultCustomerCACertPath = "/opt/cloudhsm/etc/customerCA.crt"
	VersionAnnotation         = "metadata-version"
)

func GetCredentials() (Credentials, error) {
	hsmCustomerCACertPath := os.Getenv("HSM_CUSTOMER_CA_CERT_PATH")
	if hsmCustomerCACertPath == "" {
		hsmCustomerCACertPath = DefaultCustomerCACertPath
	}
	hsmCustomerCA, err := ioutil.ReadFile(hsmCustomerCACertPath)
	if err != nil {
		return Credentials{}, fmt.Errorf("failed to read %s: %s", hsmCustomerCACertPath, err)
	}
	if len(hsmCustomerCA) == 0 {
		return Credentials{}, fmt.Errorf("%s certificate was zero bytes", hsmCustomerCACertPath)
	}
	hsmCreds := Credentials{
		IP:         os.Getenv("HSM_IP"),
		User:       os.Getenv("HSM_USER"),
		Password:   os.Getenv("HSM_PASSWORD"),
		CustomerCA: string(hsmCustomerCA),
	}
	return hsmCreds, nil
}
