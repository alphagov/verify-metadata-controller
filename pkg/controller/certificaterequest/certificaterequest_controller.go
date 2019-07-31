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
// a Deployment as an example
// Automatically generate RBAC rules to allow the Controller to read and write Deployments
// +kubebuilder:rbac:groups=verify.gov.uk,resources=certificaterequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=verify.gov.uk,resources=certificaterequests/status,verbs=get;update;patch
func (r *ReconcileCertificateRequest) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	ctx := context.Background()
	// Fetch the CertificateRequest instance
	instance := &verifyv1beta1.CertificateRequest{}
	err := r.Get(ctx, request.NamespacedName, instance)
	reconcileResult := reconcile.Result{}
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return.  Created objects are automatically garbage collected.
			// For additional cleanup logic use finalizers.
			return reconcileResult, nil
		}
		// Error reading the object - requeue the request.
		return reconcileResult, err
	}

	keyLabel := fmt.Sprintf("%s-%s", instance.ObjectMeta.Namespace, instance.ObjectMeta.Name)

	creds, err := hsm.GetCredentials()
	if err != nil {
		return reconcileResult, err
	}

	// find or create certifcate Secret
	foundSecret := &corev1.Secret{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, foundSecret)
	if err != nil && errors.IsNotFound(err) {
		_, err = r.hsm.FindOrCreateRSAKeyPair(keyLabel, creds)
		if err != nil {
			return reconcileResult, fmt.Errorf("findOrCreateRSAKeyPair(%s): %s", keyLabel, err)
		}

		req := hsm.CertRequest{
			CountryCode:      instance.Spec.CountryCode,
			CommonName:       instance.Spec.CommonName,
			ExpiryMonths:     instance.Spec.ExpiryMonths,
			Location:         instance.Spec.Location,
			Organization:     instance.Spec.Organization,
			OrganizationUnit: instance.Spec.OrganizationUnit,
			CACert:           instance.Spec.CACert,
		}

		// the hsm fn to call
		createCertFn := r.hsm.CreateSelfSignedCert

		if instance.Spec.CertificateAuthority != nil {

			reqName := types.NamespacedName{
				Name:      instance.Spec.CertificateAuthority.SecretName,
				Namespace: instance.Spec.CertificateAuthority.Namespace,
			}

			// get the cert and label saved as a secret
			caSecret := &corev1.Secret{}
			if err := r.Get(context.TODO(), reqName, caSecret); err != nil {
				return reconcileResult, err
			}

			if val, ok := caSecret.Data["cert"]; ok {
				req.ParentCertPEM = string(val)
			} else {
				return reconcileResult, fmt.Errorf("could not find 'cert' value in secret")
			}

			if val, ok := caSecret.Data["label"]; ok {
				req.ParentKeyLabel = string(val)
			} else {
				return reconcileResult, fmt.Errorf("could not find 'label' value in secret")
			}

			createCertFn = r.hsm.CreateChainedCert
		}

		cert, err := createCertFn(keyLabel, creds, req)

		if err != nil {
			return reconcileResult, fmt.Errorf("CreateChainedCert(%s): %s", keyLabel, err)
		}

		if err := r.saveSecret(instance, cert, keyLabel, creds); err != nil {
			return reconcileResult, err
		}

	} else if err != nil {
		return reconcileResult, err
	} else {
		// alredy exists, update?
	}

	return reconcileResult, nil
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
