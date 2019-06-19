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
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"

	verifyv1beta1 "github.com/alphagov/verify-metadata-controller/pkg/apis/verify/v1beta1"
	"github.com/alphagov/verify-metadata-controller/pkg/hsm"
	"github.com/mitchellh/hashstructure"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	logf "sigs.k8s.io/controller-runtime/pkg/runtime/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	cloudHSMKeyType           = "cloudhsm"
	metadataXMLKey            = "metadata.xml"
	truststorePassword        = "mashmallow"
	DefaultCustomerCACertPath = "/opt/cloudhsm/etc/customerCA.crt"
	VersionAnnotation         = "metadata-version"
)

var log = logf.Log.WithName("controller")

// Add creates a new Metadata Controller and adds it to the Manager with default RBAC. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, hsmClient hsm.Client) error {
	return add(mgr, newReconciler(mgr, hsmClient))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager, hsmClient hsm.Client) reconcile.Reconciler {
	return &ReconcileMetadata{
		Client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		hsm:    hsmClient,
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("metadata-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to Metadata
	err = c.Watch(&source.Kind{Type: &verifyv1beta1.Metadata{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Uncomment to: Watch for deleted Deployments and bring back to life
	// We have disabled this as it caused a large amount of noise as the Reconcile func would be
	// executed constantly and the self-healing of deleted resources was of limited value
	// err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
	// 	OwnerType: &verifyv1beta1.Metadata{},
	// })
	// if err != nil {
	// 	return err
	// }

	// Uncomment to: Watch for changes to created Secret
	// We have disabled this as it caused a large amount of noise as the Reconcile func would be
	// executed constantly and the self-healing of deleted resources was of limited value
	// err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
	// 	OwnerType: &verifyv1beta1.Metadata{},
	// })
	// if err != nil {
	// 	return err
	// }

	// Uncomment to: Watch for changes to created Services
	// We have disabled this as it caused a large amount of noise as the Reconcile func would be
	// executed constantly and the self-healing of deleted resources was of limited value
	// err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
	// 	OwnerType: &verifyv1beta1.Metadata{},
	// })
	// if err != nil {
	// 	return err
	// }

	return nil
}

var _ reconcile.Reconciler = &ReconcileMetadata{}

// ReconcileMetadata reconciles a Metadata object
type ReconcileMetadata struct {
	client.Client
	scheme *runtime.Scheme
	hsm    hsm.Client
}

func (r *ReconcileMetadata) generateMetadataSecretData(instance *verifyv1beta1.Metadata, metadataCreds hsm.Credentials, namespaceCreds hsm.Credentials, parentCertPEM string, parentCertKeyLabel string) (map[string][]byte, error) {
	metadataSigningKeyLabel := fmt.Sprintf("%s-%s", instance.ObjectMeta.Namespace, instance.ObjectMeta.Name)
	_, err := r.hsm.FindOrCreateRSAKeyPair(metadataSigningKeyLabel, metadataCreds)
	if err != nil {
		return nil, fmt.Errorf("findOrCreateRSAKeyPair(%s): %s", metadataSigningKeyLabel, err)
	}
	req := hsm.CertRequest{
		CountryCode:      instance.Spec.Cert.CountryCode,
		CommonName:       instance.Spec.Cert.CommonName,
		ExpiryMonths:     instance.Spec.Cert.ExpiryMonths,
		Location:         instance.Spec.Cert.Location,
		Organization:     instance.Spec.Cert.Organization,
		OrganizationUnit: instance.Spec.Cert.OrganizationUnit,
		ParentCertPEM:    parentCertPEM,
		ParentKeyLabel:   parentCertKeyLabel,
	}
	metadataSigningCert, err := r.hsm.CreateChainedCert(metadataSigningKeyLabel, metadataCreds, req)
	if err != nil {
		return nil, fmt.Errorf("CreateChainedCert(%s): %s", metadataSigningKeyLabel, err)
	}
	metadataSigningTruststore, err := generateTruststore(metadataSigningCert, metadataSigningKeyLabel, truststorePassword)
	if err != nil {
		return nil, err
	}

	signedMetadata, err := r.hsm.GenerateAndSignMetadata(metadataSigningCert, metadataSigningKeyLabel, instance.Spec, metadataCreds)
	if err != nil {
		return nil, fmt.Errorf("generateAndSignMetadata(%s): %s", metadataSigningKeyLabel, err)
	}

	// generate samlSigningCert and key
	samlSigningKeyLabel := fmt.Sprintf("%s-%s-saml", instance.ObjectMeta.Namespace, instance.ObjectMeta.Name)
	_, err := r.hsm.FindOrCreateRSAKeyPair(samlSigningKeyLabel, metadataCreds)
	if err != nil {
		return nil, fmt.Errorf("findOrCreateRSAKeyPair(%s): %s", samlSigningKeyLabel, err)
	}
	samlSigningCertReq := hsm.CertRequest{
		CountryCode:      instance.Spec.Cert.CountryCode,
		CommonName:       instance.Spec.Cert.CommonName,
		ExpiryMonths:     instance.Spec.Cert.ExpiryMonths,
		Location:         instance.Spec.Cert.Location,
		Organization:     instance.Spec.Cert.Organization,
		OrganizationUnit: instance.Spec.Cert.OrganizationUnit,
	}
	metadataSigningCert, err := r.hsm.CreateSelfSignedCert(samlSigningKeyLabel, metadataCreds, samlSigningCertReq)
	if err != nil {
		return nil, fmt.Errorf("CreateChainedCert(%s): %s", samlSigningKeyLabel, err)
	}
	samlSigningTruststore, err := generateTruststore(samlSigningCert, samlSigningKeyLabel, truststorePassword)
	if err != nil {
		return nil, err
	}
	samlSigningTruststorePassword := truststorePassword

	// generate Secret containing generated assets (including signed metadata xml)
	data := map[string][]byte{
		metadataXMLKey:                      []byte(signedMetadata),
		"entityID":                          []byte(instance.Spec.Data.EntityID),
		"postURL":                           []byte(instance.Spec.Data.PostURL),
		"redirectURL":                       []byte(instance.Spec.Data.RedirectURL),
		"metadataType":                      []byte(instance.Spec.Type),
		"metadataInternalURL":               []byte(fmt.Sprintf("http://%s/metadata.xml", instance.Name)),
		"metadataSigningKeyType":            []byte(cloudHSMKeyType),
		"metadataSigningKeyLabel":           []byte(metadataSigningKeyLabel),
		"metadataSigningCert":               []byte(metadataSigningCert),
		"metadataSigningCertBase64":         []byte(base64.StdEncoding.EncodeToString(metadataSigningCert)),
		"metadataSigningTruststore":         []byte(metadataSigningTruststore),
		"metadataSigningTruststoreBase64":   []byte(base64.StdEncoding.EncodeToString(metadataSigningTruststore)),
		"metadataSigningTruststorePassword": []byte(truststorePassword),
		"samlSigningCert":                   []byte(samlSigningCert),
		"samlSigningCertBase64":             []byte(base64.StdEncoding.EncodeToString(samlSigningCert)),
		"samlSigningTruststore":             []byte(samlSigningTruststore),
		"samlSigningTruststoreBase64":       []byte(base64.StdEncoding.EncodeToString(samlSigningTruststore)),
		"samlSigningTruststorePassword":     []byte(samlSigningTruststorePassword),
		"samlSigningKeyType":                []byte(cloudHSMKeyType),
		"samlSigningKeyLabel":               []byte(samlSigningKeyLabel),
		"hsmUser":                           []byte(metadataCreds.User),                     // <-| TODO: these should be namespaceCreds
		"hsmPassword":                       []byte(metadataCreds.Password),                 // <-|
		"hsmIP":                             []byte(metadataCreds.IP),                       // <-|
		"hsmCIDR":                           []byte(fmt.Sprintf("%s/32", metadataCreds.IP)), // <-|
		"hsmCustomerCA.crt":                 []byte(metadataCreds.CustomerCA),               // <-|
	}
	return data, nil
}

func (r *ReconcileMetadata) getCredentials() (hsm.Credentials, error) {
	hsmCustomerCACertPath := os.Getenv("HSM_CUSTOMER_CA_CERT_PATH")
	if hsmCustomerCACertPath == "" {
		hsmCustomerCACertPath = DefaultCustomerCACertPath
	}
	hsmCustomerCA, err := ioutil.ReadFile(hsmCustomerCACertPath)
	if err != nil {
		return hsm.Credentials{}, fmt.Errorf("failed to read %s: %s", hsmCustomerCACertPath, err)
	}
	if len(hsmCustomerCA) == 0 {
		return hsm.Credentials{}, fmt.Errorf("%s certificate was zero bytes", hsmCustomerCACertPath)
	}
	hsmCreds := hsm.Credentials{
		IP:         os.Getenv("HSM_IP"),
		User:       os.Getenv("HSM_USER"),
		Password:   os.Getenv("HSM_PASSWORD"),
		CustomerCA: string(hsmCustomerCA),
	}
	return hsmCreds, nil
}

// Reconcile reads that state of the cluster for a Metadata object and makes changes based on the state read
// and what is in the Metadata.Spec
// Automatically generate RBAC rules to allow the Controller to read and write Deployments
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=,resources=secrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=,resources=services/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=verify.gov.uk,resources=metadata,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=verify.gov.uk,resources=metadata/status,verbs=get;update;patch
func (r *ReconcileMetadata) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	// Fetch the Metadata instance
	instance := &verifyv1beta1.Metadata{}
	err := r.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Object not found, return.  Created objects are automatically garbage collected.
			// For additional cleanup logic use finalizers.
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	// Grab the VMC's HSM creds
	hsmCreds, err := r.getCredentials()
	if err != nil {
		return reconcile.Result{}, err
	}

	// Generate a hash of the metadata values
	currentVersionInt, err := hashstructure.Hash(instance.Spec, nil)
	if err != nil {
		return reconcile.Result{}, err
	}
	currentVersion := fmt.Sprintf("%d", currentVersionInt)

	// Find or create metadataSecret
	foundSecret := &corev1.Secret{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, foundSecret)
	if err != nil && errors.IsNotFound(err) {
		log.Info("creating-secret",
			"namespace", instance.Namespace,
			"name", instance.Name,
			"version", currentVersion,
		)
		// lookup parent/ca cert PEM+key-label data based on instance.Spec.Cert.CAName?
		parentCertPEM := "----?"
		parentCertKeyLabel := "????"
		metadataSecretData, err := r.generateMetadataSecretData(instance, hsmCreds, hsmCreds, parentCertPEM, parentCertKeyLabel) // TODO: use different hsm creds for metadata signing vs generated per-namespace keypairs
		if err != nil {
			return reconcile.Result{}, err
		}
		metadataSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      instance.Name,
				Namespace: instance.Namespace,
				Annotations: map[string]string{
					VersionAnnotation: currentVersion,
				},
			},
			Type:       corev1.SecretTypeOpaque,
			StringData: map[string]string{},
			Data:       metadataSecretData,
		}
		if err := controllerutil.SetControllerReference(instance, metadataSecret, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		err = r.Create(context.TODO(), metadataSecret)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create Secret %s: %s", metadataSecret.Name, err)
		}
		log.Info("created-secret",
			"namespace", metadataSecret.Namespace,
			"name", metadataSecret.Name,
			"version", currentVersion,
		)
	} else if err != nil {
		return reconcile.Result{}, err
	} else if foundSecret.ObjectMeta.Annotations[VersionAnnotation] != currentVersion {
		log.Info("updating-secret",
			"namespace", foundSecret.Namespace,
			"name", foundSecret.Name,
			"version", foundSecret.ObjectMeta.Annotations[VersionAnnotation],
		)
		updatedData, err := r.generateMetadataSecretData(instance, hsmCreds, hsmCreds)
		if err != nil {
			return reconcile.Result{}, err
		}
		foundSecret.ObjectMeta.Annotations[VersionAnnotation] = currentVersion
		foundSecret.Data = updatedData
		err = r.Update(context.TODO(), foundSecret)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Secret %s: %s", foundSecret.ObjectMeta.Name, err)
		}
		log.Info("updated-secret",
			"namespace", foundSecret.Namespace,
			"name", foundSecret.Name,
			"version", currentVersion,
		)
	}

	metadataLabels := map[string]string{
		"deployment": instance.Name,
	}

	metadataDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
			Annotations: map[string]string{
				VersionAnnotation: currentVersion,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: metadataLabels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: metadataLabels,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx",
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 80,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "data",
									MountPath: "/usr/share/nginx/html/metadata.xml",
									SubPath:   metadataXMLKey,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "data",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: instance.Name,
								},
							},
						},
					},
				},
			},
		},
	}
	if err := controllerutil.SetControllerReference(instance, metadataDeployment, r.scheme); err != nil {
		return reconcile.Result{}, err
	}
	// Find or create metadataDeployment
	foundDeployment := &appsv1.Deployment{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: metadataDeployment.Name, Namespace: metadataDeployment.Namespace}, foundDeployment)
	if err != nil && errors.IsNotFound(err) {
		log.Info("creating-deployment",
			"namespace", metadataDeployment.Namespace,
			"name", metadataDeployment.Name,
			"version", currentVersion,
		)
		err = r.Create(context.TODO(), metadataDeployment)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create Deployment %s: %s", metadataDeployment.Name, err)
		}
		log.Info("created-deployment",
			"namespace", metadataDeployment.Namespace,
			"name", metadataDeployment.Name,
			"version", currentVersion,
		)
	} else if err != nil {
		return reconcile.Result{}, err
	} else if foundDeployment.ObjectMeta.Annotations[VersionAnnotation] != currentVersion {
		log.Info("updating-deployment",
			"namespace", metadataDeployment.Namespace,
			"name", metadataDeployment.Name,
			"version", foundDeployment.ObjectMeta.Annotations[VersionAnnotation],
		)
		foundDeployment.Spec = metadataDeployment.Spec
		foundDeployment.ObjectMeta.Annotations[VersionAnnotation] = currentVersion
		err = r.Update(context.TODO(), foundDeployment)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Deployment %s: %s", foundDeployment.Name, err)
		}
		log.Info("updated-deployment",
			"namespace", metadataDeployment.Namespace,
			"name", metadataDeployment.Name,
			"version", currentVersion,
		)
	}

	metadataService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
			Annotations: map[string]string{
				VersionAnnotation: currentVersion,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: metadataLabels,
			Ports: []corev1.ServicePort{
				{
					Protocol:   "TCP",
					Port:       80,
					Name:       "http",
					TargetPort: intstr.FromInt(80),
				},
			},
		},
	}
	if err := controllerutil.SetControllerReference(instance, metadataService, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Find or create metadataService
	foundService := &corev1.Service{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: metadataService.Name, Namespace: metadataService.Namespace}, foundService)
	if err != nil && errors.IsNotFound(err) {
		log.Info("creating-service",
			"namespace", metadataService.Namespace,
			"name", metadataService.Name,
			"version", currentVersion,
		)
		err = r.Create(context.TODO(), metadataService)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create Service %s: %s", metadataService.Name, err)
		}
		log.Info("created-service",
			"namespace", metadataService.Namespace,
			"name", metadataService.Name,
			"version", currentVersion,
		)
	} else if err != nil {
		return reconcile.Result{}, err
	} else if foundService.ObjectMeta.Annotations[VersionAnnotation] != currentVersion {
		log.Info("updating-service",
			"namespace", metadataService.Namespace,
			"name", metadataService.Name,
			"version", foundService.ObjectMeta.Annotations[VersionAnnotation],
		)
		foundService.ObjectMeta.Annotations[VersionAnnotation] = currentVersion
		foundService.Spec.Selector = metadataLabels
		foundService.Spec.Ports = []corev1.ServicePort{
			{
				Protocol:   "TCP",
				Port:       80,
				Name:       "http",
				TargetPort: intstr.FromInt(80),
			},
		}
		err = r.Update(context.TODO(), foundService)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Service %s: %s", foundService.Name, err)
		}
		log.Info("updated-service",
			"namespace", metadataService.Namespace,
			"name", metadataService.Name,
			"version", currentVersion,
		)
	}

	return reconcile.Result{}, nil
}

func generateTruststore(cert []byte, alias, storePass string) ([]byte, error) {
	exe, err := exec.LookPath("keytool")
	if err != nil {
		return nil, err
	}
	tmpDir, err := ioutil.TempDir("", "truststore")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	tmpTruststorePath := filepath.Join(tmpDir, "cert.truststore")
	tmpCertPath := filepath.Join(tmpDir, "cert.pem")
	if err := ioutil.WriteFile(tmpCertPath, cert, 0666); err != nil {
		return nil, err
	}
	// .truststore  -trustcacerts -file hsm-proxynode-signing-cert.pem
	log.Info("generating-truststore",
		"alias", alias,
	)
	cmd := exec.Command(exe,
		"-import",
		"-noprompt",
		"-trustcacerts",
		"-alias", alias,
		"-storepass", storePass,
		"-keystore", tmpTruststorePath,
		"-file", tmpCertPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to generate truststore for %s: %s: %s", alias, out, string(cert))
	}
	b, err := ioutil.ReadFile(tmpTruststorePath)
	if err != nil {
		return nil, err
	}
	return b, nil
}
