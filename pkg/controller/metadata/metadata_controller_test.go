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
	"io/ioutil"
	"os"
	"testing"
	"time"

	verifyv1beta1 "github.com/alphagov/verify-metadata-controller/pkg/apis/verify/v1beta1"
	"github.com/alphagov/verify-metadata-controller/pkg/hsm/hsmfakes"
	. "github.com/onsi/gomega"
	"golang.org/x/net/context"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const timeout = time.Second * 5

func TestReconcile(t *testing.T) {
	ctx := context.Background()
	g := NewGomegaWithT(t)

	// Load test certs
	metadataSigningCert, err := ioutil.ReadFile("test.metadata.signing.crt")
	g.Expect(err).NotTo(HaveOccurred())

	// Setup a fake env
	os.Setenv("HSM_IP", "10.0.10.100")
	os.Setenv("HSM_USER", "hsm-user")
	os.Setenv("HSM_PASSWORD", "hsm-pass")
	os.Setenv("HSM_CUSTOMER_CA_CERT_PATH", "test.ca.crt")

	// Setup fake hsm client
	fakeSignedMetadata := []byte("<signed>FAKE-SIGNED-META</signed>")
	hsmClient := &hsmfakes.FakeClient{}
	hsmClient.FindOrCreateRSAKeyPairReturnsOnCall(0, metadataSigningCert, nil)
	hsmClient.GenerateAndSignMetadataReturnsOnCall(0, fakeSignedMetadata, nil)

	// Setup the Manager and Controller.
	mgr, err := manager.New(cfg, manager.Options{})
	g.Expect(err).NotTo(HaveOccurred())
	c := mgr.GetClient()
	recFn, requests := SetupTestReconcile(newReconciler(mgr, hsmClient), t)
	g.Expect(add(mgr, recFn)).NotTo(HaveOccurred())
	stopMgr, mgrStopped := StartTestManager(mgr, g)
	defer func() {
		close(stopMgr)
		mgrStopped.Wait()
	}()

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
		},
	}

	// Create the Metadata object and expect the Reconcile and Deployment to be created
	err = c.Create(ctx, metadataResource)
	g.Expect(err).NotTo(HaveOccurred())

	// Setup some expected things
	expectedName := types.NamespacedName{
		Name:      metadataResource.ObjectMeta.Name,
		Namespace: metadataResource.ObjectMeta.Namespace,
	}
	expectedRequest := reconcile.Request{
		NamespacedName: expectedName,
	}
	expectedLabels := map[string]string{
		"deployment": metadataResource.ObjectMeta.Name + "-deployment",
	}

	// After create the Reconcile function should be called with the expected request object
	g.Eventually(requests, timeout).Should(Receive(Equal(expectedRequest)))

	// We expect the fakehsm.FindOrCreateRSAKeyPair() to have been called
	g.Eventually(hsmClient.FindOrCreateRSAKeyPairCallCount, timeout).Should(Equal(1))

	// We expect a Secret to be created
	secretResource := &corev1.Secret{}
	getSecretResource := func() error {
		return c.Get(ctx, expectedName, secretResource)
	}
	g.Eventually(getSecretResource).Should(Succeed())
	g.Expect(secretResource.Data).To(HaveKeyWithValue("metadata.xml", fakeSignedMetadata))
	g.Expect(secretResource.Data).To(HaveKeyWithValue("entityID", []byte("https://mything/")))
	g.Expect(secretResource.Data).To(HaveKeyWithValue("postURL", []byte("https://mything/POST")))
	g.Expect(secretResource.Data).To(HaveKeyWithValue("redirectURL", []byte("https://mything/Redirect")))
	g.Expect(secretResource.Data).To(HaveKeyWithValue("hsmUser", []byte("hsm-user")))
	g.Expect(secretResource.Data).To(HaveKeyWithValue("hsmPassword", []byte("hsm-pass")))
	g.Expect(secretResource.Data).To(HaveKeyWithValue("hsmIP", []byte("10.0.10.100")))
	g.Expect(secretResource.Data).To(HaveKey("metadataSigningCert"))
	g.Expect(secretResource.Data).To(HaveKey("metadataSigningKeyLabel"))
	g.Expect(secretResource.Data).To(HaveKey("metadataSigningTruststore"))
	g.Expect(secretResource.Data).To(HaveKey("samlSigningCert"))
	g.Expect(secretResource.Data).To(HaveKey("samlSigningKeyLabel"))
	g.Expect(secretResource.Data).To(HaveKey("samlSigningTruststore"))
	g.Expect(secretResource.Data).To(HaveKey("hsmCustomerCA.crt"))
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
	g.Eventually(requests, timeout).Should(Receive(Equal(expectedRequest)))

	// a new secret should exist
	secretResource = &corev1.Secret{}
	g.Eventually(getSecretResource).Should(Succeed())
	g.Expect(secretResource.Data).To(HaveKeyWithValue("postURL", []byte("https://new-post-url/")))

	// and a new serviceResource should exist
	prevClusterIP := serviceResource.Spec.ClusterIP
	serviceResource = &corev1.Service{}
	g.Eventually(getServiceResource).Should(Succeed())

	// We expect the Service ClusterIP to be unchanged
	g.Expect(serviceResource.Spec.ClusterIP).To(Equal(prevClusterIP))
}
