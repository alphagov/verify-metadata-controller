package awscloudhsm

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"encoding/json"

	verifyv1beta1 "github.com/alphagov/verify-metadata-controller/pkg/apis/verify/v1beta1"
	"github.com/alphagov/verify-metadata-controller/pkg/hsm"
	"github.com/labstack/gommon/log"
	"gopkg.in/yaml.v2"
)

var _ hsm.Client = &Client{}

type Client struct{}

type CloudHSMToolErrorResponse struct {
	ErrorMessage	string `json:"error"`
	Stack	string `json:"stack"`
}

func (c *Client) CreateRSAKeyPair(label string, hsmCreds hsm.Credentials) (response hsm.CloudHSMToolResponse, err error) {
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
	json, errJson := cmd.Output()
	if errJson != nil {
		var errorResponse CloudHSMToolErrorResponse
		err := json.Unmarshal(errJson, &errorResponse)
		if err != nil {
			return nil, fmt.Errorf("failed to generate rsa key, could not unmarshall error json %s into struct: %s", errJson, err)
		}
		return nil, fmt.Errorf(
			"failed to generate rsa key, error from cloudhsmtool: '%s', java stack\n%s",
			errorResponse.ErrorMessage,
			errorResponse.Stack)
	}

	var res hsm.CloudHSMToolResponse
	err := json.Unmarshal(json, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key, could not unmarshall json %s into struct: %s", json, err)
	}

	if !strings.Contains(response.Certificate, "--BEGIN CERTIFICATE--") {
		return nil, fmt.Errorf("generated %s certificate does not appear to be a valid PEM format: %s", label, response.Certificate)
	}

	return res, nil
}

func (c *Client) FindOrCreateRSAKeyPair(label string, hsmCreds hsm.Credentials) (response hsm.CloudHSMToolResponse, err error) {
	return c.CreateRSAKeyPair(label, hsmCreds)
}

func (c *Client) GenerateAndSignMetadata(metadataSigningCert []byte, metadataSigningKeyLabel string, spec verifyv1beta1.MetadataSpec, hsmCreds hsm.Credentials) (signedMetadata []byte, err error) {
	if spec.Type == "" {
		return nil, fmt.Errorf("spec.Type must be set")
	}
	specFileName, err := createGeneratorFile(spec.Data)
	defer os.Remove(specFileName)
	if err != nil {
		return nil, err
	}

	tmpDir, err := ioutil.TempDir("", "mdgen")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	tmpMetadataSigningCertPath := filepath.Join(tmpDir, "cert.pem")
	tmpMetadataOutputPath := filepath.Join(tmpDir, "metadata.xml")

	if err := ioutil.WriteFile(tmpMetadataSigningCertPath, metadataSigningCert, 0644); err != nil {
		return nil, err
	}

	log.Info("mdgen",
		"type", spec.Type,
		"input", specFileName,
		"output", tmpMetadataOutputPath,
		"label", metadataSigningKeyLabel,
	)
	cmd := exec.Command("/mdgen/build/install/mdgen/bin/mdgen", spec.Type,
		specFileName, tmpMetadataSigningCertPath,
		"--output", tmpMetadataOutputPath,
		"--algorithm", "rsa",
		"--credential", "cloudhsm",
		"--hsm-key-label", metadataSigningKeyLabel,
	)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HSM_USER=%s", hsmCreds.User),
		fmt.Sprintf("HSM_PASSWORD=%s", hsmCreds.Password),
		fmt.Sprintf("HSM_IP=%s", hsmCreds.IP),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute mdgen: %s", out)
	}

	b, err := ioutil.ReadFile(tmpMetadataOutputPath)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("no metadata generated from mdgen: %s", out)
	}

	log.Info("mdgen-done",
		"metadata", string(b),
	)
	return b, nil
}

func createGeneratorFile(spec verifyv1beta1.MetadataSigningSpec) (fileName string, err error) {
	specContents, err := yaml.Marshal(
		struct {
			EntityID         string `yaml:"entity_id"`
			PostURL          string `yaml:"post_url"`
			RedirectURL      string `yaml:"redirect_url"`
			OrgName          string `yaml:"org_name"`
			OrgDisplayName   string `yaml:"org_display_name"`
			OrgURL           string `yaml:"org_url"`
			ContactCompany   string `yaml:"contact_company"`
			ContactGivenName string `yaml:"contact_given_name"`
			ContactSurname   string `yaml:"contact_surname"`
			ContactEmail     string `yaml:"contact_email"`
		}{
			EntityID:         spec.EntityID,
			PostURL:          spec.PostURL,
			RedirectURL:      spec.RedirectURL,
			OrgName:          spec.OrgName,
			OrgDisplayName:   spec.OrgDisplayName,
			OrgURL:           spec.OrgURL,
			ContactCompany:   spec.ContactCompany,
			ContactGivenName: spec.ContactGivenName,
			ContactSurname:   spec.ContactSurname,
			ContactEmail:     spec.ContactEmail,
		},
	)
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
