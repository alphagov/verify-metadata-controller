/*
Copyright 2019 GDS.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package metadata

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	verifyv1beta1 "github.com/alphagov/verify-metadata-controller/pkg/apis/verify/v1beta1"
	"github.com/alphagov/verify-metadata-controller/pkg/controller/certificaterequest"
	"github.com/alphagov/verify-metadata-controller/pkg/hsm/hsmfakes"
	. "github.com/onsi/gomega"
	"golang.org/x/net/context"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const timeout = time.Second * 5

func TestReconcile(t *testing.T) {
	ctx := context.Background()
	g := NewGomegaWithT(t)

	// Load test certs
	fakeMetadataCert, err := ioutil.ReadFile("test.metadata.signing.crt")
	g.Expect(err).NotTo(HaveOccurred())
	fakeSamlCert := fakeMetadataCert
	fakeIntCert := fakeMetadataCert
	fakeRootCert := fakeMetadataCert
	fakeCustomerCA, err := ioutil.ReadFile("test.ca.crt")
	g.Expect(err).NotTo(HaveOccurred())

	// Setup a fake env
	os.Setenv("HSM_IP", "10.0.10.100")
	os.Setenv("HSM_USER", "hsm-user")
	os.Setenv("HSM_PASSWORD", "hsm-pass")
	os.Setenv("HSM_CUSTOMER_CA_CERT_PATH", "test.ca.crt")

	// Setup fake hsm client
	fakeSignedMetadata := []byte("<signed>FAKE-SIGNED-META</signed>")
	hsmClient := &hsmfakes.FakeClient{}
	hsmClient.FindOrCreateRSAKeyPairReturns([]byte("----BEGIN PUB KEY----"), nil)
	hsmClient.GenerateAndSignMetadataReturns(fakeSignedMetadata, nil)
	hsmClient.CreateSelfSignedCertReturnsOnCall(0, fakeRootCert, nil)
	hsmClient.CreateSelfSignedCertReturnsOnCall(1, fakeSamlCert, nil)
	hsmClient.CreateSelfSignedCertReturnsOnCall(2, fakeSamlCert, nil)
	hsmClient.CreateSelfSignedCertReturnsOnCall(3, fakeSamlCert, nil)
	hsmClient.CreateChainedCertReturnsOnCall(0, fakeIntCert, nil)
	hsmClient.CreateChainedCertReturnsOnCall(1, fakeMetadataCert, nil)
	hsmClient.CreateChainedCertReturnsOnCall(2, fakeMetadataCert, nil)
	hsmClient.CreateChainedCertReturnsOnCall(3, fakeMetadataCert, nil)

	// Setup the Manager and Controller.
	mgr, err := manager.New(cfg, manager.Options{})
	g.Expect(err).NotTo(HaveOccurred())
	c := mgr.GetClient()
	metaRecFn, reconcileMetadataCallCount := SetupTestReconcile(NewReconciler(mgr, hsmClient), t)
	g.Expect(AddReconciler(mgr, metaRecFn)).To(Succeed())
	certRecFn, reconcileCertRequestCallCount := SetupTestReconcile(certificaterequest.NewReconciler(mgr, hsmClient), t)
	g.Expect(certificaterequest.AddReconciler(mgr, certRecFn)).To(Succeed())
	stopMgr, mgrStopped := StartTestManager(mgr, g)
	defer func() {
		close(stopMgr)
		mgrStopped.Wait()
	}()

	tearDownCerts := generateCertChain(t, ctx, c, g)
	defer tearDownCerts(t)

	// The Reconcile function should have been called twice by now
	g.Eventually(reconcileCertRequestCallCount, timeout).Should(Equal(3))
	g.Consistently(reconcileCertRequestCallCount, timeout).Should(Equal(3))

	// flesh out a metadata object
	metadataResource := &verifyv1beta1.Metadata{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: verifyv1beta1.MetadataSpec{
			ID:   "_entities",
			Type: "proxy",
			Data: verifyv1beta1.MetadataSigningSpec{
				EntityID:         "https://mything/",
				PostURL:          "https://mything/POST",
				RedirectURL:      "https://mything/Redirect",
				OrgName:          "orig-org-name",
				OrgDisplayName:   "Original Org Name",
				OrgURL:           "https://org1.com",
				ContactCompany:   "O",
				ContactGivenName: "jeff",
				ContactSurname:   "jefferson",
				ContactEmail:     "jeff@jeff.com",
				ValidityDays:     0,
			},
			CertificateAuthority: verifyv1beta1.CertificateAuthoritySpec{
				SecretName: "meta",
				Namespace:  "default",
			},
			SAMLSigningCertificate: &verifyv1beta1.CertificateRequestSpec{
				CountryCode:      "GB",
				CommonName:       "SAML Signing Cert",
				ExpiryMonths:     6,
				Location:         "London",
				Organization:     "GDS",
				OrganizationUnit: "Verify",
				CACert:           false,
				CertificateAuthority: &verifyv1beta1.CertificateAuthoritySpec{
					SecretName: "root",
					Namespace:  "cert-system",
				},
			},
		},
	}

	// Create the Metadata object and expect the Reconcile and Deployment to be created
	err = c.Create(ctx, metadataResource)
	g.Expect(err).NotTo(HaveOccurred())
	defer func() {
		metadataName := types.NamespacedName{
			Name:      metadataResource.ObjectMeta.Name,
			Namespace: metadataResource.ObjectMeta.Namespace,
		}
		metadataResource := &verifyv1beta1.Metadata{}
		c.Get(ctx, metadataName, metadataResource)
		c.Delete(ctx, metadataResource)
	}()

	// Setup some expected things
	expectedName := types.NamespacedName{
		Name:      metadataResource.ObjectMeta.Name,
		Namespace: metadataResource.ObjectMeta.Namespace,
	}
	expectedLabels := map[string]string{
		"deployment": metadataResource.ObjectMeta.Name,
	}

	// The Reconcile function should have been called exactly once so far
	g.Eventually(reconcileMetadataCallCount, timeout).Should(Equal(1))
	g.Consistently(reconcileMetadataCallCount, timeout).Should(Equal(1))

	// We expect the fakehsm.FindOrCreateRSAKeyPair() to have been called:
	// * once to create the self signed Root CA's keypair
	// * once to create the Int CA's keypair
	// * once to create the Metadata Cert's keypair
	// * once to create the self signed SAML cert's keypair
	g.Eventually(hsmClient.FindOrCreateRSAKeyPairCallCount, timeout).Should(Equal(4))

	// We expect a Secret to be created
	secretResource := &corev1.Secret{}
	getSecretResource := func() error {
		return c.Get(ctx, expectedName, secretResource)
	}
	g.Eventually(getSecretResource).Should(Succeed())
	g.Expect(secretResource.ObjectMeta.Annotations).ShouldNot(BeNil())
	g.Expect(secretResource.ObjectMeta.Annotations[versionAnnotation]).ShouldNot(Equal(""))

	// We expect the Secret Data values to be generated from Metadata
	getSecretData := func(key string) func() ([]byte, error) {
		return func() ([]byte, error) {
			s := &corev1.Secret{}
			if err := c.Get(ctx, expectedName, s); err != nil {
				return nil, err
			}
			return s.Data[key], nil
		}
	}

	g.Eventually(getSecretData("metadata.xml")).Should(Equal(fakeSignedMetadata))
	g.Eventually(getSecretData("entityID")).Should(Equal([]byte("https://mything/")))
	g.Eventually(getSecretData("postURL")).Should(Equal([]byte("https://mything/POST")))
	g.Eventually(getSecretData("redirectURL")).Should(Equal([]byte("https://mything/Redirect")))
	g.Eventually(getSecretData("hsmUser")).Should(Equal([]byte("hsm-user")))
	g.Eventually(getSecretData("hsmPassword")).Should(Equal([]byte("hsm-pass")))
	g.Eventually(getSecretData("hsmIP")).Should(Equal([]byte("10.0.10.100")))
	g.Eventually(getSecretData("metadataSigningCert")).Should(Equal(fakeMetadataCert))
	g.Eventually(getSecretData("metadataSigningTruststore")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("metadataSigningKeyLabel")).Should(Equal([]byte("default-meta")))
	g.Eventually(getSecretData("samlSigningCert")).Should(Equal(fakeSamlCert))
	g.Eventually(getSecretData("samlSigningTruststore")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("samlSigningKeyLabel")).Should(Equal([]byte("default-foo-saml")))
	g.Eventually(getSecretData("hsmCustomerCA.crt")).Should(Equal(fakeCustomerCA))
	g.Eventually(getSecretData("metadataCATruststore")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("metadataCATruststoreBase64")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("metadataCACerts")).Should(Equal(bytes.Join([][]byte{fakeRootCert, fakeIntCert}, []byte("\n"))))
	g.Eventually(getSecretData("publishingPath")).Should(Equal([]byte("metadata.xml")))
	g.Eventually(getSecretData("validityDays")).Should(Equal([]byte("30")))

	byteValidUntil, _ := getSecretData("validUntil")()

	g.Eventually(checkDateIsInRange(t, byteValidUntil)).Should(Equal(true))
	// TODO: add the rest of the Secret fields here...

	// We expect a an nginx Deployment to be created with the same name
	deploymentResource := &appsv1.Deployment{}
	getDeploymentResource := func() error {
		return c.Get(ctx, expectedName, deploymentResource)
	}
	g.Eventually(getDeploymentResource).Should(Succeed())
	g.Expect(deploymentResource.Spec.Selector.MatchLabels).To(Equal(expectedLabels))
	g.Expect(deploymentResource.Spec.Template.Spec.Containers).To(HaveLen(1))
	g.Expect(deploymentResource.Spec.Template.Spec.Containers[0].Image).To(Equal("nginx"))
	g.Expect(deploymentResource.Spec.Template.ObjectMeta.Labels).To(Equal(expectedLabels))

	// We expect a Service to be created in same namespace
	serviceResource := &corev1.Service{}
	getServiceResource := func() error {
		return c.Get(ctx, expectedName, serviceResource)
	}
	g.Eventually(getServiceResource).Should(Succeed())
	g.Expect(serviceResource.Spec.Ports).To(HaveLen(1))
	g.Expect(serviceResource.Spec.Ports[0].Name).To(Equal("http"))
	g.Expect(serviceResource.Spec.Ports[0].Protocol).To(Equal(corev1.Protocol("TCP")))
	g.Expect(serviceResource.Spec.Ports[0].Port).To(Equal(int32(80)))
	g.Expect(serviceResource.Spec.Ports[0].TargetPort).To(Equal(intstr.FromInt(80)))
	g.Expect(serviceResource.Spec.Selector).To(Equal(expectedLabels))
	g.Expect(serviceResource.Spec.ClusterIP).NotTo(Equal(corev1.ClusterIPNone))
	g.Expect(serviceResource.Spec.ClusterIP).NotTo(Equal(""))

	// Update the metadata
	metadataResourceUpdated := metadataResource
	metadataResourceUpdated.Spec.Data.PostURL = "https://new-post-url/"
	g.Expect(c.Update(ctx, metadataResourceUpdated)).To(Succeed())

	// After updating the Metadata Reconcile should have been called again
	g.Eventually(reconcileMetadataCallCount, timeout).Should(Equal(2))

	// We expect the Secret data field(s) to get updated
	g.Eventually(getSecretData("postURL")).Should(Equal([]byte("https://new-post-url/")))

	// and a new serviceResource should exist
	prevClusterIP := serviceResource.Spec.ClusterIP
	serviceResource = &corev1.Service{}
	g.Eventually(getServiceResource).Should(Succeed())

	// We expect the Service ClusterIP to be unchanged
	g.Expect(serviceResource.Spec.ClusterIP).To(Equal(prevClusterIP))

	// Update the metadata a third time, but with no changes that affect generated metadata
	metadataResourceUpdated.ObjectMeta.Annotations = map[string]string{
		"inconsequental-annotation": "nothing-to-see-here",
	}
	g.Expect(c.Update(ctx, metadataResourceUpdated)).To(Succeed())

	// After updating the Metadata Reconcile should have been called again
	g.Eventually(reconcileMetadataCallCount, timeout).Should(Equal(3))

	// We expect the fakehsm.FindOrCreateRSAKeyPair() to have been called:
	// * 4x earlier (see above)
	// * 2x after update (signingCert and samlCert)
	// * 0x after second update?
	g.Eventually(hsmClient.FindOrCreateRSAKeyPairCallCount, timeout).Should(Equal(6))

	// We do not expecyt the Reconcile func to have been called more than 3 times (create, update, update)
	g.Consistently(reconcileMetadataCallCount, timeout).Should(Equal(3))
}

func TestReconcileMetadataWithProvidedCerts(t *testing.T) {
	ctx := context.Background()
	g := NewGomegaWithT(t)

	// Load test certs
	fakeMetadataCert, err := ioutil.ReadFile("test.metadata.signing.crt")
	g.Expect(err).NotTo(HaveOccurred())
	fakeSamlCert := fakeMetadataCert
	fakeIntCert := fakeMetadataCert
	fakeRootCert := fakeMetadataCert

	suppliedSigningCert, err := ioutil.ReadFile("test.saml.signing.crt")
	g.Expect(err).NotTo(HaveOccurred())
	suppliedEncryptionCert, err := ioutil.ReadFile("test.saml.encryption.crt")
	g.Expect(err).NotTo(HaveOccurred())

	// Setup a fake env
	os.Setenv("HSM_IP", "10.0.10.100")
	os.Setenv("HSM_USER", "hsm-user")
	os.Setenv("HSM_PASSWORD", "hsm-pass")
	os.Setenv("HSM_CUSTOMER_CA_CERT_PATH", "test.ca.crt")

	// Setup fake hsm client
	fakeSignedMetadata := []byte("<signed>FAKE-SIGNED-META</signed>")
	hsmClient := &hsmfakes.FakeClient{}
	hsmClient.FindOrCreateRSAKeyPairReturns([]byte("----BEGIN PUB KEY----"), nil)
	hsmClient.GenerateAndSignMetadataReturns(fakeSignedMetadata, nil)
	hsmClient.CreateSelfSignedCertReturnsOnCall(0, fakeRootCert, nil)
	hsmClient.CreateSelfSignedCertReturnsOnCall(1, fakeSamlCert, nil)
	hsmClient.CreateSelfSignedCertReturnsOnCall(2, fakeSamlCert, nil)
	hsmClient.CreateChainedCertReturnsOnCall(0, fakeIntCert, nil)
	hsmClient.CreateChainedCertReturnsOnCall(1, fakeMetadataCert, nil)
	hsmClient.CreateChainedCertReturnsOnCall(2, fakeMetadataCert, nil)
	hsmClient.CreateChainedCertReturnsOnCall(3, fakeMetadataCert, nil)

	// Setup the Manager and Controller.
	mgr, err := manager.New(cfg, manager.Options{})
	g.Expect(err).NotTo(HaveOccurred())
	c := mgr.GetClient()
	metaRecFn, reconcileMetadataCallCount := SetupTestReconcile(NewReconciler(mgr, hsmClient), t)
	g.Expect(AddReconciler(mgr, metaRecFn)).To(Succeed())
	certRecFn, _ := SetupTestReconcile(certificaterequest.NewReconciler(mgr, hsmClient), t)
	g.Expect(certificaterequest.AddReconciler(mgr, certRecFn)).To(Succeed())
	stopMgr, mgrStopped := StartTestManager(mgr, g)
	defer func() {
		close(stopMgr)
		mgrStopped.Wait()
	}()

	teardownCerts := generateCertChain(t, ctx, c, g)
	defer teardownCerts(t)

	// flesh out a metadata object
	metadataResource := &verifyv1beta1.Metadata{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "metadata-from-supplied-certs",
			Namespace: "default",
		},
		Spec: verifyv1beta1.MetadataSpec{
			ID:   "_entities",
			Type: "proxy",
			Data: verifyv1beta1.MetadataSigningSpec{
				EntityID:                  "https://mything/",
				PostURL:                   "https://mything/POST",
				RedirectURL:               "https://mything/Redirect",
				OrgName:                   "orig-org-name",
				OrgDisplayName:            "Original Org Name",
				OrgURL:                    "https://org1.com",
				ContactCompany:            "O",
				ContactGivenName:          "jeff",
				ContactSurname:            "jefferson",
				ContactEmail:              "jeff@jeff.com",
				SamlSigningCertificate:    string(suppliedSigningCert),
				SamlEncryptionCertificate: string(suppliedEncryptionCert),
			},
			CertificateAuthority: verifyv1beta1.CertificateAuthoritySpec{
				SecretName: "meta",
				Namespace:  "default",
			},
			PublishingPath: "ConnectorMetadata",
		},
	}

	// Create the Metadata object and expect the Reconcile and Deployment to be created
	err = c.Create(ctx, metadataResource)
	g.Expect(err).NotTo(HaveOccurred())

	// The Reconcile function should have been called exactly once so far
	g.Eventually(reconcileMetadataCallCount, timeout).Should(Equal(1))
	g.Consistently(reconcileMetadataCallCount, timeout).Should(Equal(1))

	// Setup some expected things
	expectedName := types.NamespacedName{
		Name:      metadataResource.ObjectMeta.Name,
		Namespace: metadataResource.ObjectMeta.Namespace,
	}

	// We expect a Secret to be created
	secretResource := &corev1.Secret{}
	getSecretResource := func() error {
		return c.Get(ctx, expectedName, secretResource)
	}
	g.Eventually(getSecretResource).Should(Succeed())
	g.Expect(secretResource.ObjectMeta.Annotations).ShouldNot(BeNil())
	g.Expect(secretResource.ObjectMeta.Annotations[versionAnnotation]).ShouldNot(Equal(""))

	// We expect the Secret Data values to be generated from Metadata
	getSecretData := func(key string) func() ([]byte, error) {
		return func() ([]byte, error) {
			s := &corev1.Secret{}
			if err := c.Get(ctx, expectedName, s); err != nil {
				return nil, err
			}
			return s.Data[key], nil
		}
	}

	g.Eventually(getSecretData("metadata.xml")).Should(Equal(fakeSignedMetadata))
	g.Eventually(getSecretData("entityID")).Should(Equal([]byte("https://mything/")))
	g.Eventually(getSecretData("postURL")).Should(Equal([]byte("https://mything/POST")))
	g.Eventually(getSecretData("redirectURL")).Should(Equal([]byte("https://mything/Redirect")))
	g.Eventually(getSecretData("metadataSigningCert")).Should(Equal(fakeMetadataCert))
	g.Eventually(getSecretData("metadataSigningTruststore")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("metadataSigningKeyLabel")).Should(Equal([]byte("default-meta")))
	g.Eventually(getSecretData("publishingPath")).Should(Equal([]byte("ConnectorMetadata")))
	g.Eventually(getSecretData("samlSigningCert")).Should(Equal(formatCertString(string(suppliedSigningCert))))
	g.Eventually(getSecretData("samlSigningTruststore")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("samlSigningKeyLabel")).Should(Equal([]byte("default-metadata-from-supplied-certs-saml")))
	g.Eventually(getSecretData("samlEncryptionCert")).Should(Equal(formatCertString(string(suppliedEncryptionCert))))
	g.Eventually(getSecretData("metadataCATruststore")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("metadataCATruststoreBase64")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("metadataCACerts")).Should(Equal(bytes.Join([][]byte{fakeRootCert, fakeIntCert}, []byte("\n"))))
	g.Eventually(getSecretData("hsmUser")).Should(BeNil())
	g.Eventually(getSecretData("hsmPassword")).Should(BeNil())
	g.Eventually(getSecretData("hsmIP")).Should(BeNil())
	g.Eventually(getSecretData("hsmCustomerCA.crt")).Should(BeNil())
}

func TestShouldRegenerate(t *testing.T) {
	g := NewGomegaWithT(t)

	const ConstantHash = "Im a constant hash"

	mockMetadata := verifyv1beta1.Metadata{}
	mockMetadata.Namespace = "Namespace"
	mockMetadata.Name = "Name"

	mockSecrets := corev1.Secret{}
	mockSecrets.ObjectMeta.Annotations = make(map[string]string)
	mockSecrets.Data = make(map[string][]byte)

	// Hashes should differ, so should be true to regenerate
	mockSecrets.ObjectMeta.Annotations[versionAnnotation] = ""
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeTrue())

	// Hash should now match, but there is no data for the expiration, this simulates a upgrade.
	mockSecrets.ObjectMeta.Annotations[versionAnnotation] = ConstantHash
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeTrue())

	// There should be a parse error.
	mockSecrets.Data[validityDays] = []byte("30")
	mockSecrets.Data[validUntil] = []byte("")
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeTrue())

	// Should regenerate as time is in the past.
	mockSecrets.Data[validUntil] = []byte(time.Now().AddDate(0, 0, -1).Format(time.RFC1123Z))
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeTrue())

	// Should regenerate if half of the validity days.
	mockSecrets.Data[validUntil] = []byte(time.Now().AddDate(0, 0, 15).Format(time.RFC1123Z))
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeTrue())

	// Shouldn't regenerate if more than half of the validity days.
	mockSecrets.Data[validUntil] = []byte(time.Now().AddDate(0, 0, 15).Add(time.Duration(time.Minute)).Format(time.RFC1123Z))
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeFalse())

	// Shouldn't regenerate as in the future.
	mockSecrets.Data[validUntil] = []byte(time.Now().AddDate(0, 0, 60).Format(time.RFC1123Z))
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeFalse())

	// Should work with odd values of validityDays
	mockSecrets.Data[validityDays] = []byte("1")
	mockSecrets.Data[validUntil] = []byte(time.Now().Format(time.RFC1123Z))
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeTrue())

	mockSecrets.Data[validUntil] = []byte(time.Now().Add(time.Duration(time.Hour * 12)).Format(time.RFC1123Z))
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeTrue())

	mockSecrets.Data[validUntil] = []byte(time.Now().Add(time.Duration(time.Hour*12 + time.Minute)).Format(time.RFC1123Z))
	g.Eventually(ShouldRegenerate(&mockSecrets, ConstantHash, mockMetadata)).Should(BeFalse())
}

func checkDateIsInRange(t *testing.T, byteStrInputDate []byte) bool {
	t.Helper()
	timeObjInputDate, _ := time.Parse(time.RFC1123Z, string(byteStrInputDate))

	currentTime := time.Now().AddDate(0, 0, 30)

	beforeTime := currentTime.Add(-30 * time.Second)
	afterTime := currentTime.Add(30 * time.Second)

	return timeObjInputDate.After(beforeTime) && timeObjInputDate.Before(afterTime)
}

type certDetails struct {
	name               string
	namespace          string
	commonName         string
	caCert             bool
	authorityName      string
	authorityNamespace string
}

func generateCertChain(t *testing.T, ctx context.Context, c client.Client, g *GomegaWithT) func(t *testing.T) {
	t.Helper()
	certs := []certDetails{
		{
			"root",
			"cert-system",
			"RootCA",
			true,
			"",
			"",
		},
		{
			"int",
			"cert-system",
			"IntermediateCA",
			true,
			"root",
			"cert-system",
		},
		{
			"meta",
			"default",
			"MetadataSigningCert",
			false,
			"int",
			"cert-system",
		},
	}

	rootCertReq := &verifyv1beta1.CertificateRequest{}
	rootSecret := &corev1.Secret{}
	createCert(t, certs[0], rootCertReq, rootSecret, ctx, c, g)

	intCertReq := &verifyv1beta1.CertificateRequest{}
	intSecret := &corev1.Secret{}
	createCert(t, certs[1], intCertReq, intSecret, ctx, c, g)

	metaCertReq := &verifyv1beta1.CertificateRequest{}
	metaSecret := &corev1.Secret{}
	createCert(t, certs[2], metaCertReq, metaSecret, ctx, c, g)

	tearDown := func(t *testing.T) {
		g.Eventually(func() error {
			return c.Delete(ctx, rootCertReq)
		}).Should(Succeed())
		g.Eventually(func() error {
			return c.Delete(ctx, rootSecret)
		}).Should(Succeed())

		g.Eventually(func() error {
			return c.Delete(ctx, intCertReq)
		}).Should(Succeed())
		g.Eventually(func() error {
			return c.Delete(ctx, intSecret)
		}).Should(Succeed())

		g.Eventually(func() error {
			return c.Delete(ctx, metaCertReq)
		}).Should(Succeed())
		g.Eventually(func() error {
			return c.Delete(ctx, metaSecret)
		}).Should(Succeed())
	}

	return tearDown
}

func createCert(t *testing.T, details certDetails, req *verifyv1beta1.CertificateRequest, secret *corev1.Secret, ctx context.Context, c client.Client, g *GomegaWithT) {
	t.Helper()
	req.ObjectMeta = metav1.ObjectMeta{
		Name:      details.name,
		Namespace: details.namespace,
	}

	req.Spec = verifyv1beta1.CertificateRequestSpec{
		CountryCode:      "GB",
		CommonName:       details.commonName,
		ExpiryMonths:     12,
		Location:         "London",
		Organization:     "Cab",
		OrganizationUnit: "GDS",
		CACert:           details.caCert,
	}

	if details.authorityName != "" {
		req.Spec.CertificateAuthority = &verifyv1beta1.CertificateAuthoritySpec{
			SecretName: details.authorityName,
			Namespace:  details.authorityNamespace,
		}
	}
	namespacedName := types.NamespacedName{
		Name:      req.ObjectMeta.Name,
		Namespace: req.ObjectMeta.Namespace,
	}

	err := c.Create(ctx, req)
	g.Expect(err).ToNot(HaveOccurred())

	g.Eventually(func() error {
		return c.Get(ctx, namespacedName, secret)
	}).Should(Succeed())
}
