package hsm

type Credentials struct {
	IP         string
	User       string
	Password   string
	CustomerCA string
}

type GenerateMetadataRequest struct {
	MetadataSigningCert     []byte
	SAMLSigningCert         []byte
	SAMLEncryptionCert      []byte
	MetadataSigningKeyLabel string
	SamlSigningKeyLabel     string
	Type                    string
	HSMCreds                Credentials
	Data                    MetadataRequestData
	HSMSAMLSigning          bool
}

type MetadataRequestData struct {
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
}

type Client interface {
	CreateRSAKeyPair(label string, hsmCreds Credentials) (publicCert []byte, err error)
	FindOrCreateRSAKeyPair(label string, hsmCreds Credentials) (signingCert []byte, err error)
	GenerateAndSignMetadata(request GenerateMetadataRequest) (signedMetadata []byte, err error)
	CreateSelfSignedCert(label string, hsmCreds Credentials, req CertRequest) ([]byte, error)
	CreateChainedCert(label string, hsmCreds Credentials, req CertRequest) ([]byte, error)
}
