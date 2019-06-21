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

package certificaterequest

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	verifyv1beta1 "github.com/alphagov/verify-metadata-controller/pkg/apis/verify/v1beta1"
	"github.com/alphagov/verify-metadata-controller/pkg/hsm/hsmfakes"
	. "github.com/onsi/gomega"
	"golang.org/x/net/context"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var c client.Client

const timeout = time.Second * 5

func TestReconcileRootCA(t *testing.T) {
	ctx := context.Background()
	g := NewGomegaWithT(t)

	// Setup a fake env
	HSM_IP := "10.0.10.101"
	HSM_USER := "hsm-user"
	HSM_PASSWORD := "hsm-passw"
	HSM_CUSTOMER_CA_CERT_PATH := "test.ca.crt"
	HSM_CUSTOMER_CA, err := ioutil.ReadFile(HSM_CUSTOMER_CA_CERT_PATH)
	g.Expect(err).ToNot(HaveOccurred())
	os.Setenv("HSM_IP", HSM_IP)
	os.Setenv("HSM_USER", HSM_USER)
	os.Setenv("HSM_PASSWORD", HSM_PASSWORD)
	os.Setenv("HSM_CUSTOMER_CA_CERT_PATH", HSM_CUSTOMER_CA_CERT_PATH)

	// Setup fake hsm client
	fakePublicKey := []byte("-----BEGIN FAKE PUB KEY-----")
	fakeCertData := []byte("-----BEGIN FAKE SELF SIGNED CERT-----")
	hsmClient := &hsmfakes.FakeClient{}
	hsmClient.FindOrCreateRSAKeyPairReturns(fakePublicKey, nil)
	hsmClient.CreateSelfSignedCertReturns(fakeCertData, nil)

	// Setup the Manager and Controller.
	mgr, err := manager.New(cfg, manager.Options{})
	g.Expect(err).NotTo(HaveOccurred())
	c := mgr.GetClient()
	recFn, reconcileCallCount := SetupTestReconcile(newReconciler(mgr, hsmClient), t)
	g.Expect(add(mgr, recFn)).NotTo(HaveOccurred())
	stopMgr, mgrStopped := StartTestManager(mgr, g)
	defer func() {
		close(stopMgr)
		mgrStopped.Wait()
	}()

	// someone adds a cert request for a Root CA...
	req := &verifyv1beta1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "root",
			Namespace: "foo",
		},
		Spec: verifyv1beta1.CertificateRequestSpec{
			CountryCode:      "GB",
			CommonName:       "CertyMcCertFace",
			ExpiryMonths:     15,
			Location:         "London",
			Organization:     "Cab",
			OrganizationUnit: "GDS",
			CACert:           true,
		},
	}
	err = c.Create(ctx, req)
	g.Expect(err).To(Succeed())

	// The Reconcile function should have been called exactly once
	g.Eventually(reconcileCallCount, timeout).Should(Equal(1))
	g.Consistently(reconcileCallCount, timeout).Should(Equal(1))

	// key label should be in the form $NAMESPACE-$NAME
	expectedLabelName := "foo-root"

	// expect: key pair generated for the label with creds
	g.Eventually(hsmClient.FindOrCreateRSAKeyPairCallCount, timeout).Should(Equal(1))
	createKeyLabel, createKeyCreds := hsmClient.FindOrCreateRSAKeyPairArgsForCall(0)
	g.Expect(createKeyCreds.IP).Should(Equal(HSM_IP))
	g.Expect(createKeyCreds.User).Should(Equal(HSM_USER))
	g.Expect(createKeyCreds.Password).Should(Equal(HSM_PASSWORD))
	g.Expect(createKeyCreds.CustomerCA).Should(Equal(string(HSM_CUSTOMER_CA)))
	g.Expect(createKeyLabel).Should(Equal(expectedLabelName))

	// expect CreateSelfSignedCert to have been called with the label
	g.Eventually(hsmClient.CreateSelfSignedCertCallCount, timeout).Should(Equal(1))
	createCertLabel, createCertCreds, createCertReq := hsmClient.CreateSelfSignedCertArgsForCall(0)
	g.Expect(createCertLabel).Should(Equal(expectedLabelName))
	g.Expect(createCertCreds.IP).Should(Equal(HSM_IP))
	g.Expect(createCertCreds.User).Should(Equal(HSM_USER))
	g.Expect(createCertCreds.Password).Should(Equal(HSM_PASSWORD))
	g.Expect(createCertCreds.CustomerCA).Should(Equal(string(HSM_CUSTOMER_CA)))
	g.Expect(createCertReq.CountryCode).Should(Equal(req.Spec.CountryCode))
	g.Expect(createCertReq.CommonName).Should(Equal(req.Spec.CommonName))
	g.Expect(createCertReq.ExpiryMonths).Should(Equal(req.Spec.ExpiryMonths))
	g.Expect(createCertReq.Location).Should(Equal(req.Spec.Location))
	g.Expect(createCertReq.Organization).Should(Equal(req.Spec.Organization))
	g.Expect(createCertReq.OrganizationUnit).Should(Equal(req.Spec.OrganizationUnit))

	// expect a secret to have been created
	reqName := types.NamespacedName{
		Name:      req.ObjectMeta.Name,
		Namespace: req.ObjectMeta.Namespace,
	}
	caSecret := &corev1.Secret{}
	getSecret := func() error {
		return c.Get(ctx, reqName, caSecret)
	}
	g.Eventually(getSecret).Should(Succeed())

	// expect generated secret to have some data
	g.Expect(caSecret.Data).ToNot(BeNil())

	// expect: certificate placed into a Secret
	// expect: label in the Secret
	// expect: hsm creds for the label
	g.Expect(caSecret.Data["cert"]).To(Equal(fakeCertData))
	g.Expect(caSecret.Data["label"]).To(Equal([]byte(expectedLabelName)))
	g.Expect(caSecret.Data["hsmIP"]).To(Equal([]byte(HSM_IP)))
	g.Expect(caSecret.Data["hsmUser"]).To(Equal([]byte(HSM_USER)))
	g.Expect(caSecret.Data["hsmPassword"]).To(Equal([]byte(HSM_PASSWORD)))
	g.Expect(caSecret.Data["hsmCustomerCA"]).To(Equal([]byte(HSM_CUSTOMER_CA)))

	// update should not error
	err = c.Update(ctx, req)
	g.Expect(err).To(Succeed())

	// delete should not error
	err = c.Delete(ctx, req)
	g.Expect(err).To(Succeed())
}
