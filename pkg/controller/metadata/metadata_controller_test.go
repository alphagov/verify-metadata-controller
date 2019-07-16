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
	"k8s.io/apimachinery/pkg/util/intstr"
	"os"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"testing"
	"time"

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

	rootCertReq, intCertReq, metaCertReq, tearDownCerts := generateCertChain(t, ctx, c, g)
	defer tearDownCerts(t)

	// The Reconcile function should have been called twice by now
	g.Eventually(reconcileCertRequestCallCount, timeout).Should(Equal(3))
	g.Consistently(reconcileCertRequestCallCount, timeout).Should(Equal(3))

	// expect a secret to exist for root cert req
	g.Eventually(func() error {
		name := types.NamespacedName{
			Name:      rootCertReq.ObjectMeta.Name,
			Namespace: rootCertReq.ObjectMeta.Namespace,
		}
		s := &corev1.Secret{}
		return c.Get(ctx, name, s)
	}).Should(Succeed())
	// expect a secret to exist for intermediate cert req
	g.Eventually(func() error {
		name := types.NamespacedName{
			Name:      intCertReq.ObjectMeta.Name,
			Namespace: intCertReq.ObjectMeta.Namespace,
		}
		s := &corev1.Secret{}
		return c.Get(ctx, name, s)
	}).Should(Succeed())
	// expect a secret to exist for metadata cert req
	g.Eventually(func() error {
		name := types.NamespacedName{
			Name:      metaCertReq.ObjectMeta.Name,
			Namespace: metaCertReq.ObjectMeta.Namespace,
		}
		s := &corev1.Secret{}
		return c.Get(ctx, name, s)
	}).Should(Succeed())

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
	g.Expect(secretResource.ObjectMeta.Annotations[VersionAnnotation]).ShouldNot(Equal(""))

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
	g.Eventually(getSecretData("metadataCACerts")).Should(Equal(bytes.Join([][]byte{fakeRootCert, fakeIntCert, fakeMetadataCert}, []byte("\n"))))
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
	g.Eventually(hsmClient.FindOrCreateRSAKeyPairCallCount, timeout).Should(Equal(5))

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

	generateCertChain(t, ctx, c, g)

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
				EntityID:              "https://mything/",
				PostURL:               "https://mything/POST",
				RedirectURL:           "https://mything/Redirect",
				OrgName:               "orig-org-name",
				OrgDisplayName:        "Original Org Name",
				OrgURL:                "https://org1.com",
				ContactCompany:        "O",
				ContactGivenName:      "jeff",
				ContactSurname:        "jefferson",
				ContactEmail:          "jeff@jeff.com",
				SigningCertificate:    string(suppliedSigningCert),
				EncryptionCertificate: string(suppliedEncryptionCert),
			},
			CertificateAuthority: verifyv1beta1.CertificateAuthoritySpec{
				SecretName: "meta",
				Namespace:  "default",
			},
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
	g.Expect(secretResource.ObjectMeta.Annotations[VersionAnnotation]).ShouldNot(Equal(""))

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
	g.Eventually(getSecretData("samlSigningCert")).Should(Equal(suppliedSigningCert))
	g.Eventually(getSecretData("samlSigningTruststore")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("samlSigningKeyLabel")).Should(Equal([]byte("default-metadata-from-supplied-certs-saml")))
	g.Eventually(getSecretData("samlEncryptionCert")).Should(Equal(suppliedEncryptionCert))
	g.Eventually(getSecretData("metadataCATruststore")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("metadataCATruststoreBase64")).ShouldNot(Equal([]byte{}))
	g.Eventually(getSecretData("metadataCACerts")).Should(Equal(bytes.Join([][]byte{fakeRootCert, fakeIntCert, fakeMetadataCert}, []byte("\n"))))
	g.Eventually(getSecretData("hsmUser")).Should(BeNil())
	g.Eventually(getSecretData("hsmPassword")).Should(BeNil())
	g.Eventually(getSecretData("hsmIP")).Should(BeNil())
	g.Eventually(getSecretData("hsmCustomerCA.crt")).Should(BeNil())

}

func generateCertChain(t *testing.T, ctx context.Context, c client.Client, g *GomegaWithT) (*verifyv1beta1.CertificateRequest, *verifyv1beta1.CertificateRequest, *verifyv1beta1.CertificateRequest, func(t *testing.T)) {

	// create fake root certificate request
	rootCertReq := &verifyv1beta1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root",
			Namespace: "cert-system",
		},
		Spec: verifyv1beta1.CertificateRequestSpec{
			CountryCode:      "GB",
			CommonName:       "RootCA",
			ExpiryMonths:     12,
			Location:         "London",
			Organization:     "Cab",
			OrganizationUnit: "GDS",
			CACert:           true,
		},
	}

	err := c.Create(ctx, rootCertReq)
	g.Expect(err).ToNot(HaveOccurred())

	// create fake intermediate certificate request
	intCertReq := &verifyv1beta1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "int",
			Namespace: "cert-system",
		},
		Spec: verifyv1beta1.CertificateRequestSpec{
			CountryCode:      "GB",
			CommonName:       "IntermediateCA",
			ExpiryMonths:     12,
			Location:         "London",
			Organization:     "Cab",
			OrganizationUnit: "GDS",
			CACert:           true,
			CertificateAuthority: &verifyv1beta1.CertificateAuthoritySpec{
				SecretName: "root",
				Namespace:  "cert-system",
			},
		},
	}
	err = c.Create(ctx, intCertReq)
	g.Expect(err).ToNot(HaveOccurred())

	// create fake metadata certificate request
	metaCertReq := &verifyv1beta1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "meta",
			Namespace: "default",
		},
		Spec: verifyv1beta1.CertificateRequestSpec{
			CountryCode:      "GB",
			CommonName:       "MetadataSigngingCert",
			ExpiryMonths:     12,
			Location:         "London",
			Organization:     "Cab",
			OrganizationUnit: "GDS",
			CACert:           false,
			CertificateAuthority: &verifyv1beta1.CertificateAuthoritySpec{
				SecretName: "int",
				Namespace:  "cert-system",
			},
		},
	}
	err = c.Create(ctx, metaCertReq)
	g.Expect(err).ToNot(HaveOccurred())

	tearDown := func(t *testing.T) {
		rootName := types.NamespacedName{
			Name:      rootCertReq.ObjectMeta.Name,
			Namespace: rootCertReq.ObjectMeta.Namespace,
		}
		rootRequest := &verifyv1beta1.CertificateRequest{}
		_ = c.Get(ctx, rootName, rootRequest)
		_ = c.Delete(ctx, rootRequest)
		rootSecret := &corev1.Secret{}
		_ = c.Get(ctx, rootName, rootSecret)
		_ = c.Delete(ctx, rootSecret)

		intName := types.NamespacedName{
			Name:      intCertReq.ObjectMeta.Name,
			Namespace: intCertReq.ObjectMeta.Namespace,
		}
		intRequest := &verifyv1beta1.CertificateRequest{}
		_ = c.Get(ctx, intName, intRequest)
		_ = c.Delete(ctx, intRequest)
		intSecret := &corev1.Secret{}
		_ = c.Get(ctx, intName, intSecret)
		_ = c.Delete(ctx, intSecret)

		metaName := types.NamespacedName{
			Name:      metaCertReq.ObjectMeta.Name,
			Namespace: metaCertReq.ObjectMeta.Namespace,
		}
		metaRequest := &verifyv1beta1.CertificateRequest{}
		_ = c.Get(ctx, metaName, metaRequest)
		_ = c.Delete(ctx, metaRequest)
		metadataSecret := &corev1.Secret{}
		_ = c.Get(ctx, metaName, metadataSecret)
		_ = c.Delete(ctx, metadataSecret)
	}

	return rootCertReq, intCertReq, metaCertReq, tearDown
}
