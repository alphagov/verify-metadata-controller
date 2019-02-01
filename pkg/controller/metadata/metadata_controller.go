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
	"strings"

	verifyv1beta1 "github.com/alphagov/verify-metadata-controller/pkg/apis/verify/v1beta1"
	"gopkg.in/yaml.v2"
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
	cloudHSMKeyType    = "cloudhsm"
	metadataXMLKey     = "metadata.xml"
	truststorePassword = "mashmallow"
)

var log = logf.Log.WithName("controller")

// Add creates a new Metadata Controller and adds it to the Manager with default RBAC. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileMetadata{Client: mgr.GetClient(), scheme: mgr.GetScheme()}
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

	// Watch for changes to created Deployments
	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		OwnerType: &verifyv1beta1.Metadata{},
	})
	if err != nil {
		return err
	}

	// Watch for changes to created Secret
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		OwnerType: &verifyv1beta1.Metadata{},
	})
	if err != nil {
		return err
	}

	// Watch for changes to created Services
	err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
		OwnerType: &verifyv1beta1.Metadata{},
	})
	if err != nil {
		return err
	}

	return nil
}

var _ reconcile.Reconciler = &ReconcileMetadata{}

// ReconcileMetadata reconciles a Metadata object
type ReconcileMetadata struct {
	client.Client
	scheme *runtime.Scheme
}

type HSMCredentials struct {
	IP         string
	User       string
	Password   string
	CustomerCA string
}

func createRSAKeyPair(label string, hsmCreds HSMCredentials) (publicCert []byte, err error) {
	log.Info("cloudhsmtool",
		"command", "genrsa",
		"label", label,
	)
	cmd := exec.Command("/cloudhsmtool/build/install/cloudhsmtool/bin/cloudhsmtool",
		"genrsa", label,
	)
	cmd.Stderr = nil // when nil stderr output is captured in err from Output
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HSM_USER=%s", hsmCreds.User),
		fmt.Sprintf("HSM_PASSWORD=%s", hsmCreds.Password),
		fmt.Sprintf("HSM_IP=%s", hsmCreds.IP),
	)
	cert, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key for %s: %s", label, err)
	}
	if !strings.Contains(string(cert), "--BEGIN CERTIFICATE--") {
		return nil, fmt.Errorf("generated %s certificate does not appear to be a valid PEM format: %s", label, cert)
	}
	return cert, nil
}

func findOrCreateRSAKeyPair(label string, hsmCreds HSMCredentials) (signingCert []byte, err error) {
	return createRSAKeyPair(label, hsmCreds)
}

func generateMetadataSecret(instance *verifyv1beta1.Metadata, metadataCreds HSMCredentials, namespaceCreds HSMCredentials) (*corev1.Secret, error) {

	metadataSigningKeyLabel := "metadata"
	metadataSigningCert, err := findOrCreateRSAKeyPair(metadataSigningKeyLabel, metadataCreds)
	if err != nil {
		return nil, fmt.Errorf("findOrCreateRSAKeyPair(%s): %s", metadataSigningKeyLabel, err)
	}
	metadataSigningTruststore, err := generateTruststore(metadataSigningCert, metadataSigningKeyLabel, truststorePassword)
	if err != nil {
		return nil, err
	}

	signedMetadata, err := generateAndSignMetadata(metadataSigningCert, metadataSigningKeyLabel, instance.Spec, metadataCreds)
	if err != nil {
		return nil, fmt.Errorf("generateAndSignMetadata(%s): %s", metadataSigningKeyLabel, err)
	}

	// right now the samlSigning* certs/keys is same as metadataSigning* certs/keys
	// TODO findOrCreateRSAKeyPair for samlSigningCert using namespaceCreds instead of using metadata keypair
	samlSigningCert := metadataSigningCert
	samlSigningKeyLabel := metadataSigningKeyLabel
	samlSigningTruststore := metadataSigningTruststore
	samlSigningTruststorePassword := truststorePassword

	// TODO findOrCreateRSAKeyPair for samlEncryptionCert namespaceCreds instead of using metadata keypair
	// samlEncryptionCert := metadataSigningCert
	// etc...

	// generate Secret containing generated assets (including signed metadata xml)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
		Type:       corev1.SecretTypeOpaque,
		StringData: map[string]string{},
		Data: map[string][]byte{
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
			"hsmUser":                           []byte(metadataCreds.User),       // <-| TODO: these should be namespaceCreds
			"hsmPassword":                       []byte(metadataCreds.Password),   // <-|
			"hsmIP":                             []byte(metadataCreds.IP),         // <-|
			"hsmCustomerCA.crt":                 []byte(metadataCreds.CustomerCA), // <-|
			// "samlEncryptionCert":               samlEncyptionCert,
			// "samlEncryptionCertBase64":         samlEncyptionCertBase64,
			// "samlEncryptionTruststoreBase64":   samlEncryptionTruststoreBase64,
			// "samlEncryptionTruststorePassword": samlEncryptionTruststorePassword,
			// "samlEncryptionKeyLabel":           samlEncryptionKeyLabel,
			// "samlEncryptionTruststore":        samlEncryptionTruststore,
			// .. etc
		},
	}
	return secret, nil
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

	// Find or create metadataSecret
	foundSecret := &corev1.Secret{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: instance.Name, Namespace: instance.Namespace}, foundSecret)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Generating Secret", "namespace", instance.Namespace, "name", instance.Name)
		hsmCustomerCACertPath := "/opt/cloudhsm/etc/customerCA.crt"
		hsmCustomerCA, err := ioutil.ReadFile(hsmCustomerCACertPath)
		if err != nil {
			return reconcile.Result{}, err
		}
		hsmCreds := HSMCredentials{
			IP:         os.Getenv("HSM_IP"),
			User:       os.Getenv("HSM_USER"),
			Password:   os.Getenv("HSM_PASSWORD"),
			CustomerCA: string(hsmCustomerCA),
		}

		metadataSecret, err := generateMetadataSecret(instance, hsmCreds, hsmCreds) // TODO: use different hsm creds for metadata signing vs generated per-namespace keypairs
		if err != nil {
			log.Error(err, "generating-metadata")
			return reconcile.Result{}, err
		}
		if err := controllerutil.SetControllerReference(instance, metadataSecret, r.scheme); err != nil {
			return reconcile.Result{}, err
		}
		log.Info("Creating Secret", "namespace", metadataSecret.Namespace, "name", metadataSecret.Name)
		err = r.Create(context.TODO(), metadataSecret)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create Secret %s: %s", metadataSecret.Name, err)
		}
	} else if err != nil {
		return reconcile.Result{}, err
	} else {
		// TODO: we may want to handle updates to self-heal metadata, but this would need to be more inteligent than below
	}

	metadataLabels := map[string]string{
		"deployment": instance.Name + "-deployment",
	}

	metadataDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
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
		log.Info("Creating Deployment", "namespace", metadataDeployment.Namespace, "name", metadataDeployment.Name)
		err = r.Create(context.TODO(), metadataDeployment)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create Deployment %s: %s", metadataDeployment.Name, err)
		}
	} else if err != nil {
		return reconcile.Result{}, err
	} else {
		// TODO: Update deployment if changed
	}

	metadataService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: metadataLabels,
			Ports: []corev1.ServicePort{
				{
					Protocol:   "TCP",
					Port:       80,
					TargetPort: intstr.FromInt(80),
				},
			},
			ClusterIP: corev1.ClusterIPNone,
		},
	}
	if err := controllerutil.SetControllerReference(instance, metadataService, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Find or create metadataService
	foundService := &corev1.Service{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: metadataService.Name, Namespace: metadataService.Namespace}, foundService)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating Service", "namespace", metadataService.Namespace, "name", metadataService.Name)
		err = r.Create(context.TODO(), metadataService)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to create Service %s: %s", metadataService.Name, err)
		}
	} else if err != nil {
		return reconcile.Result{}, err
	} else {
		// TODO: Update resource if changed
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
	log.Info("Generating truststore",
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
		return nil, fmt.Errorf("failed to generate truststore for %s: %s", alias, out)
	}
	b, err := ioutil.ReadFile(tmpTruststorePath)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func generateAndSignMetadata(metadataSigningCert []byte, metadataSigningKeyLabel string, spec verifyv1beta1.MetadataSpec, hsmCreds HSMCredentials) (signedMetadata []byte, err error) {
	if spec.Type == "" {
		return nil, fmt.Errorf("spec.Type must be set")
	}
	specFileName, err := createGeneratorFile(spec.Data)
	defer os.Remove(specFileName)
	if err != nil {
		return nil, err
	}

	tmpDir, err := ioutil.TempDir("", "mdgen")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	tmpMetadataSigningCertPath := filepath.Join(tmpDir, "cert.pem")
	tmpMetadataOutputPath := filepath.Join(tmpDir, "metadata.xml")

	if err := ioutil.WriteFile(tmpMetadataSigningCertPath, metadataSigningCert, 0644); err != nil {
		return nil, err
	}

	log.Info("mdgen",
		"type", spec.Type,
		"input", specFileName,
		"output", tmpMetadataOutputPath,
		"label", metadataSigningKeyLabel,
	)
	cmd := exec.Command("/mdgen/build/install/mdgen/bin/mdgen", spec.Type,
		specFileName, tmpMetadataSigningCertPath,
		"--output", tmpMetadataOutputPath,
		"--algorithm", "rsa",
		"--credential", "cloudhsm",
		"--hsm-key-label", metadataSigningKeyLabel,
	)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HSM_USER=%s", hsmCreds.User),
		fmt.Sprintf("HSM_PASSWORD=%s", hsmCreds.Password),
		fmt.Sprintf("HSM_IP=%s", hsmCreds.IP),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute mdgen: %s", out)
	}

	b, err := ioutil.ReadFile(tmpMetadataOutputPath)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("no metadata generated from mdgen: %s", out)
	}

	log.Info("mdgen-done",
		"metadata", string(b),
	)
	return b, nil
}

func createGeneratorFile(spec verifyv1beta1.MetadataSigningSpec) (fileName string, err error) {
	specContents, err := yaml.Marshal(
		struct {
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
		}{
			EntityID:         spec.EntityID,
			PostURL:          spec.PostURL,
			RedirectURL:      spec.RedirectURL,
			OrgName:          spec.OrgName,
			OrgDisplayName:   spec.OrgDisplayName,
			OrgURL:           spec.OrgURL,
			ContactCompany:   spec.ContactCompany,
			ContactGivenName: spec.ContactGivenName,
			ContactSurname:   spec.ContactSurname,
			ContactEmail:     spec.ContactEmail,
		},
	)
	if err != nil {
		return "", err
	}

	specFile, err := ioutil.TempFile("", "sign_spec")
	if err != nil {
		return "", err
	}
	defer specFile.Close()

	_, err = specFile.Write(specContents)
	if err != nil {
		return "", err
	}

	return specFile.Name(), nil
}
