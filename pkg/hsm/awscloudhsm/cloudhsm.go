package awscloudhsm

import (
	"fmt"
	"github.com/alphagov/verify-metadata-controller/pkg/hsm"
	"github.com/labstack/gommon/log"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
)

var _ hsm.Client = &Client{}

type Client struct{}

func (c *Client) CreateRSAKeyPair(label string, hsmCreds hsm.Credentials) ([]byte, error) {
	log.Info("cloudhsmtool",
		"command", "genrsa",
		"label", label,
	)
	cmd := exec.Command("/cloudhsmtool/build/install/cloudhsmtool/bin/cloudhsmtool",
		"genrsa", label,
	)
	cmd.Stderr = nil // when nil stderr output is captured in err from Output
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HSM_USER=%s", hsmCreds.User),
		fmt.Sprintf("HSM_PASSWORD=%s", hsmCreds.Password),
		fmt.Sprintf("HSM_IP=%s", hsmCreds.IP),
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key for %s: %s", label, err)
	}
	return out, nil
}

func (c *Client) FindOrCreateRSAKeyPair(label string, hsmCreds hsm.Credentials) (signingCert []byte, err error) {
	return c.CreateRSAKeyPair(label, hsmCreds)
}

func (c *Client) CreateSelfSignedCert(label string, hsmCreds hsm.Credentials, req hsm.CertRequest) ([]byte, error) {
	log.Info("cloudhsmtool",
		"command", "genrsa",
		"label", label,
	)
	args := []string{
		"create-self-signed-cert", label,
		"-C", req.CountryCode,
		"-CN", req.CommonName,
		"-expiry", fmt.Sprintf("%d", req.ExpiryMonths),
		"-L", req.Location,
		"-O", req.Organization,
		"-OU", req.OrganizationUnit,
	}
	cmd := exec.Command("/cloudhsmtool/build/install/cloudhsmtool/bin/cloudhsmtool", args...)
	cmd.Stderr = nil // when nil stderr output is captured in err from Output
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HSM_USER=%s", hsmCreds.User),
		fmt.Sprintf("HSM_PASSWORD=%s", hsmCreds.Password),
		fmt.Sprintf("HSM_IP=%s", hsmCreds.IP),
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key for %s: %s", label, err)
	}
	return out, nil
}

func (c *Client) CreateChainedCert(label string, hsmCreds hsm.Credentials, req hsm.CertRequest) ([]byte, error) {
	log.Info("cloudhsmtool",
		"command", "genrsa",
		"label", label,
	)
	args := []string{
		"create-chained-cert", label,
		"-C", req.CountryCode,
		"-CN", req.CommonName,
		"-expiry", fmt.Sprintf("%d", req.ExpiryMonths),
		"-L", req.Location,
		"-O", req.Organization,
		"-OU", req.OrganizationUnit,
		"-parent-cert-base64", req.ParentCertPEM,
		"-parent-key-label", req.ParentKeyLabel,
	}
	if req.CACert {
		args = append(args, "-ca-cert")
	}
	cmd := exec.Command("/cloudhsmtool/build/install/cloudhsmtool/bin/cloudhsmtool", args...)
	cmd.Stderr = nil // when nil stderr output is captured in err from Output
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HSM_USER=%s", hsmCreds.User),
		fmt.Sprintf("HSM_PASSWORD=%s", hsmCreds.Password),
		fmt.Sprintf("HSM_IP=%s", hsmCreds.IP),
	)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key for %s: %s", label, err)
	}
	return out, nil
}

func (c *Client) GenerateAndSignMetadata(request hsm.GenerateMetadataRequest) (signedMetadata []byte, err error) {
	if request.Type == "" {
		return nil, fmt.Errorf("spec.Type must be set")
	}
	specFileName, err := createGeneratorFile(request.Data)
	defer os.Remove(specFileName)
	if err != nil {
		return nil, err
	}

	tmpDir, err := ioutil.TempDir("", "mdgen")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	tmpMetadataSigningCertPath := filepath.Join(tmpDir, "metadata-cert.pem")
	tmpSAMLSigningCertPath := filepath.Join(tmpDir, "saml-signing-cert.pem")
	tmpSAMLEncryptionCertPath := filepath.Join(tmpDir, "saml-encryption-cert.pem")
	tmpMetadataOutputPath := filepath.Join(tmpDir, "metadata.xml")

	if err := ioutil.WriteFile(tmpMetadataSigningCertPath, request.MetadataSigningCert, 0644); err != nil {
		return nil, err
	}

	if err := ioutil.WriteFile(tmpSAMLSigningCertPath, request.SAMLSigningCert, 0644); err != nil {
		return nil, err
	}

	if err := ioutil.WriteFile(tmpSAMLEncryptionCertPath, request.SAMLEncryptionCert, 0644); err != nil {
		return nil, err
	}

	log.Info("mdgen",
		"type", request.Type,
		"input", specFileName,
		"output", tmpMetadataOutputPath,
		"metadataSigningKeyLabel", request.MetadataSigningKeyLabel,
		"samlSigningKeyLabel", request.SamlSigningKeyLabel,
		"samlEncryptionCert", request.SAMLEncryptionCert,
	)
	cmd := exec.Command("/mdgen/build/install/mdgen/bin/mdgen",
		request.Type,
		specFileName,
		tmpSAMLSigningCertPath,
		tmpMetadataSigningCertPath,
		"--output", tmpMetadataOutputPath,
		"--algorithm", "rsa",
		"--hsm-metadata-signing-label", request.MetadataSigningKeyLabel,
		"--hsm-saml-signing-label", request.SamlSigningKeyLabel,
		"--saml-encryption-cert", tmpSAMLEncryptionCertPath,
	)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HSM_USER=%s", request.HSMCreds.User),
		fmt.Sprintf("HSM_PASSWORD=%s", request.HSMCreds.Password),
		fmt.Sprintf("HSM_IP=%s", request.HSMCreds.IP),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute mdgen: %s", out)
	}

	metadata, err := ioutil.ReadFile(tmpMetadataOutputPath)
	if err != nil {
		return nil, err
	}
	if len(metadata) == 0 {
		return nil, fmt.Errorf("no metadata generated from mdgen: %s", out)
	}

	log.Info("mdgen-done",
		"metadata", string(metadata),
	)
	return metadata, nil
}

func createGeneratorFile(data hsm.MetadataRequestData) (fileName string, err error) {
	specContents, err := yaml.Marshal(data)
	if err != nil {
		return "", err
	}

	specFile, err := ioutil.TempFile("", "sign_spec")
	if err != nil {
		return "", err
	}
	defer specFile.Close()

	_, err = specFile.Write(specContents)
	if err != nil {
		return "", err
	}

	return specFile.Name(), nil
}
