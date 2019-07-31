package hsm

type CertRequest struct {
	CountryCode      string
	CommonName       string
	ExpiryMonths     int
	Location         string
	Organization     string
	OrganizationUnit string
	ParentCertPEM    string
	ParentKeyLabel   string
	CACert           bool
}
