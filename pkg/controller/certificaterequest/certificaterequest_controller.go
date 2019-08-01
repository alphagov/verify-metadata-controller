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
	"context"
	"fmt"
	verifyv1beta1 "github.com/alphagov/verify-metadata-controller/pkg/apis/verify/v1beta1"
	"github.com/alphagov/verify-metadata-controller/pkg/hsm"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
	"strconv"
	"time"
)

var log = logf.Log.WithName("controller")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new CertificateRequest Controller and adds it to the Manager with default RBAC. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, hsmClient hsm.Client) error {
	return AddReconciler(mgr, NewReconciler(mgr, hsmClient))
}

// NewReconciler returns a new reconcile.Reconciler
func NewReconciler(mgr manager.Manager, hsmClient hsm.Client) reconcile.Reconciler {
	return &ReconcileCertificateRequest{
		Client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		hsm:    hsmClient,
	}
}

// AddReconciler adds a new Controller to mgr with r as the reconcile.Reconciler
func AddReconciler(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("certificaterequest-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to CertificateRequest
	err = c.Watch(&source.Kind{Type: &verifyv1beta1.CertificateRequest{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileCertificateRequest{}

// ReconcileCertificateRequest reconciles a CertificateRequest object
type ReconcileCertificateRequest struct {
	client.Client
	scheme *runtime.Scheme
	hsm    hsm.Client
}

// Reconcile reads that state of the cluster for a CertificateRequest object and makes changes based on the state read
// and what is in the CertificateRequest.Spec
// Automatically generate RBAC rules to allow the Controller to read and write CertificateRequests
// +kubebuilder:rbac:groups=verify.gov.uk,resources=certificaterequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=verify.gov.uk,resources=certificaterequests/status,verbs=get;update;patch
func (r *ReconcileCertificateRequest) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	ctx := context.Background()
	reconcileResult := reconcile.Result{}
	// Fetch the CertificateRequest certReconcileRequest
	certReconcileRequest := &verifyv1beta1.CertificateRequest{}
	err := r.Get(ctx, request.NamespacedName, certReconcileRequest)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return.  Created objects are automatically garbage collected.
			// For additional cleanup logic use finalizers.
			return reconcileResult, nil
		}
		// Error reading the object - requeue the request.
		return reconcileResult, err
	}

	hsmCredentials, err := hsm.GetCredentials()
	if err != nil {
		return reconcileResult, err
	}

	// find or create certificate Secret
	keyLabel := fmt.Sprintf("%s-%s", certReconcileRequest.ObjectMeta.Namespace, certReconcileRequest.ObjectMeta.Name)
	foundSecret := &corev1.Secret{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: certReconcileRequest.Name, Namespace: certReconcileRequest.Namespace}, foundSecret)
	if isNotFoundError(err) {

		// cert is not present in the secret, so ensure there is a keypair in hsm for cert generation
		if _, err := r.hsm.FindOrCreateRSAKeyPair(keyLabel, hsmCredentials); err != nil {
			return reconcileResult, fmt.Errorf("findOrCreateRSAKeyPair(%s): %s", keyLabel, err)
		}

		cert, err := r.createCert(certReconcileRequest, keyLabel)
		if err != nil {
			return reconcileResult, fmt.Errorf("error with createCert: %s", err)
		}

		if err := r.saveSecret(certReconcileRequest, cert, keyLabel, hsmCredentials); err != nil {
			return reconcileResult, err
		}

	} else if err != nil {
		return reconcileResult, err
	} else {

		certDueToExpireTime := r.certDueToExpireTime(foundSecret, err, certReconcileRequest)
		if time.Now().After(certDueToExpireTime) {

			// delete the current secret
			// TODO investigate delete options propogating to delete other cert secrets
			if err := r.Delete(context.TODO(), foundSecret); err != nil {
				return reconcileResult, fmt.Errorf("coud not delete current cert secret: %s", err)
			}

			// create a new cert signed by current hsm keypair
			cert, err := r.createCert(certReconcileRequest, keyLabel)
			if err != nil {
				return reconcileResult, fmt.Errorf("error with createCert: %s", err)
			}

			// create a new secret containing new cert
			if err := r.saveSecret(certReconcileRequest, cert, keyLabel, hsmCredentials); err != nil {
				return reconcileResult, err
			}
		}
	}

	// TODO investigate decorating the reconcileResult with RequeueAfter so it will ensure being called again in say 1 day (a cheap rescheduling)
	return reconcileResult, nil
}

func (r *ReconcileCertificateRequest) certDueToExpireTime(foundSecret *corev1.Secret, err error, certReconcileRequest *verifyv1beta1.CertificateRequest) time.Time {
	// the cert is present, check if it is expiring
	var expiryMonths int
	if exp, ok := foundSecret.Data["expiryMonths"]; ok {
		expiryMonths, err = strconv.Atoi(string(exp))
	} else {
		// update secret with spec expiry
		foundSecret.Data["expiryMonths"] = []byte(strconv.Itoa(certReconcileRequest.Spec.ExpiryMonths))
		r.Update(context.TODO(), foundSecret)
	}
	// due to expire if date of secret creation plus expiryInMonths minus 7 days is greater than now
	dueToExpireTime := foundSecret.CreationTimestamp.AddDate(0, expiryMonths, 0).AddDate(0, 0, -7)
	return dueToExpireTime
}

func (r *ReconcileCertificateRequest) saveSecret(instance *verifyv1beta1.CertificateRequest, cert []byte, keyLabel string, creds hsm.Credentials) error {

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{},
		Data: map[string][]byte{
			"cert":          cert,
			"label":         []byte(keyLabel),
			"hsmUser":       []byte(creds.User),
			"hsmPassword":   []byte(creds.Password),
			"hsmIP":         []byte(creds.IP),
			"hsmCustomerCA": []byte(creds.CustomerCA),
			"expiryMonths":  []byte(strconv.Itoa(instance.Spec.ExpiryMonths)),
		},
	}

	if err := controllerutil.SetControllerReference(instance, secret, r.scheme); err != nil {
		return err
	}

	if err := r.Create(context.TODO(), secret); err != nil {
		return err
	}

	log.Info("created-certificate-secret",
		"namespace", secret.Namespace,
		"name", secret.Name,
	)

	return nil
}

func (r *ReconcileCertificateRequest) createCert(certReconcileRequest *verifyv1beta1.CertificateRequest, keyLabel string) ([]byte, error) {

	certRequest := createCertRequest(certReconcileRequest)

	// the hsm fn to call
	createCertFn := r.hsm.CreateSelfSignedCert

	// if the spec indicates a CertificateAuthority, that is the CA for this cert
	if certReconcileRequest.Spec.CertificateAuthority != nil {

		reqForCACertSecret := types.NamespacedName{
			Name:      certReconcileRequest.Spec.CertificateAuthority.SecretName,
			Namespace: certReconcileRequest.Spec.CertificateAuthority.Namespace,
		}

		// get the cert and label saved as a secret
		caSecret := &corev1.Secret{}
		if err := r.Get(context.TODO(), reqForCACertSecret, caSecret); err != nil {
			return nil, err
		}

		if val, ok := caSecret.Data["cert"]; ok {
			certRequest.ParentCertPEM = string(val)
		} else {
			return nil, fmt.Errorf("could not find 'cert' value in secret")
		}

		if val, ok := caSecret.Data["label"]; ok {
			certRequest.ParentKeyLabel = string(val)
		} else {
			return nil, fmt.Errorf("could not find 'label' value in secret")
		}

		createCertFn = r.hsm.CreateChainedCert
	}

	hsmCredentials, err := hsm.GetCredentials()
	if err != nil {
		return nil, err
	}

	cert, err := createCertFn(keyLabel, hsmCredentials, certRequest)
	if err != nil {
		return nil, fmt.Errorf("CreateChainedCert(%s): %s", keyLabel, err)
	}
	return cert, nil
}

func isNotFoundError(err error) bool {
	return err != nil && errors.IsNotFound(err)
}

func createCertRequest(certReconcileRequest *verifyv1beta1.CertificateRequest) hsm.CertRequest {
	return hsm.CertRequest{
		CountryCode:      certReconcileRequest.Spec.CountryCode,
		CommonName:       certReconcileRequest.Spec.CommonName,
		ExpiryMonths:     certReconcileRequest.Spec.ExpiryMonths,
		Location:         certReconcileRequest.Spec.Location,
		Organization:     certReconcileRequest.Spec.Organization,
		OrganizationUnit: certReconcileRequest.Spec.OrganizationUnit,
		CACert:           certReconcileRequest.Spec.CACert,
	}
}
