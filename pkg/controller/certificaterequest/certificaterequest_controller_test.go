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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var c client.Client

var expectedRequest = reconcile.Request{NamespacedName: types.NamespacedName{Name: "foo"}}
var depKey = types.NamespacedName{Name: "foo-deployment", Namespace: "default"}

const timeout = time.Second * 5

func TestReconcile(t *testing.T) {
	ctx := context.Background()
	g := NewGomegaWithT(t)

	// Setup a fake env
	os.Setenv("HSM_IP", "10.0.10.100")
	os.Setenv("HSM_USER", "hsm-user")
	os.Setenv("HSM_PASSWORD", "hsm-pass")
	os.Setenv("HSM_CUSTOMER_CA_CERT_PATH", "test.ca.crt")

	// Setup fake hsm client
	fakePublicKey := []byte("-----BEGIN KEY THING-----")
	fakeCertData := []byte("-----BEGIN FAKE CERT-----")
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
	caReq := &verifyv1beta1.CertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "root", Namespace:"namespace-foo"},
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
	err = c.Create(ctx, caReq)
	g.Expect(err).To(Succeed())

	// The Reconcile function should have been called exactly once
	g.Eventually(reconcileCallCount, timeout).Should(Equal(1))
	g.Consistently(reconcileCallCount, timeout).Should(Equal(1))

	// expect: key pair generated for a particular label
	expectedLabelName := caReq.ObjectMeta.Name
	g.Eventually(func() string {
		if hsmClient.FindOrCreateRSAKeyPairCallCount() > 0 {
			label, _ := hsmClient.FindOrCreateRSAKeyPairArgsForCall(0)
			return label
		}
		return ""
	}, timeout).Should(Equal(expectedLabelName))

	// expect a secret to have been created
	caReqName := types.NamespacedName{
		Name:      caReq.ObjectMeta.Name,
		Namespace: caReq.ObjectMeta.Namespace,
	}
	caSecret := &corev1.Secret{}
	getSecret := func() error {
		return c.Get(ctx, caReqName, caSecret)
	}
	g.Eventually(getSecret).Should(Succeed())

	// expect: certificate placed into a Secret
	// expect: label in the Secret
	// expect: hsm creds for the label
	getSecretData := func(key string) func() ([]byte, error) {
		return func() ([]byte, error) {
			s := &corev1.Secret{}
			if err := c.Get(ctx, caReqName, s); err != nil {
				return nil, err
			}
			return s.Data[key], nil
		}
	}
	g.Eventually(getSecretData("cert")).Should(Equal(fakeCertData))
	g.Eventually(getSecretData("label")).Should(Equal([]byte(expectedLabelName)))
	g.Eventually(getSecretData("hsmUser")).Should(Equal([]byte("hsm-user")))
	g.Eventually(getSecretData("hsmPassword")).Should(Equal([]byte("hsm-pass")))
	g.Eventually(getSecretData("hsmIP")).Should(Equal([]byte("10.0.10.100")))

	// .. then same again with a parent

}
