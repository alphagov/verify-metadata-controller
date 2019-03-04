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
	"reflect"

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
		IsController: true,
		OwnerType:    &verifyv1beta1.Metadata{},
	})
	if err != nil {
		return err
	}

	// Watch for changes to created ConfigMaps
	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &verifyv1beta1.Metadata{},
	})
	if err != nil {
		return err
	}

	// Watch for changes to created Services
	err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &verifyv1beta1.Metadata{},
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

// Reconcile reads that state of the cluster for a Metadata object and makes changes based on the state read
// and what is in the Metadata.Spec
// Automatically generate RBAC rules to allow the Controller to read and write Deployments
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=deployments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=,resources=configmaps/status,verbs=get;update;patch
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

	metadataSigningCertPath := "/etc/verify-proxy-node/hsm_signing_cert.pem"
	metadataSigningKeyLabel := "proxynode"
	metadataSigningCert, err := ioutil.ReadFile(metadataSigningCertPath)
	if err != nil {
		log.Error(err, "reading-metadata-signing-cert")
		return reconcile.Result{}, err
	}
	metadataSigningTruststorePassword := "mashmallow"
	metadataSigningTruststore, err := createTruststore(metadataSigningCert, metadataSigningTruststorePassword)

	signedMetadata, err := generateAndSignMetadata(metadataSigningCertPath, metadataSigningKeyLabel, instance.Spec)
	if err != nil {
		log.Error(err, "generating-metadata")
		return reconcile.Result{}, err
	}

	// TODO generate metadataSigningKey for metadataSigningKeyLabel if missing and fetch pub key
	// TODO generate metadataSigningCert if missing
	// TODO generate signingKey for signingKeyLabel if missing and fetch pub key
	// TODO generate signingCert with signingKey if missing or expired
	// TODO generate encryptionKey for encryptionKeyLabel if missing and fetch pub key
	// TODO generate encryptionCert with encryptionKey if missing and fetch pub key

	// generate ConfigMap containing signedMetadata
	metadataConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: instance.Namespace,
		},
		BinaryData: map[string][]byte{
			"metadata.xml":                      signedMetadata,
			"metadataInternalURL":               []byte(fmt.Sprintf("http://%s/metadata.xml", instance.Name)),
			"metadataSigningCert":               metadataSigningCert,
			"metadataSigningCertBase64":         []byte(base64.StdEncoding.EncodeToString(metadataSigningCert)),
			"metadataSigningTruststore":         metadataSigningTruststore,
			"metadataSigningTruststoreBase64":   []byte(base64.StdEncoding.EncodeToString(metadataSigningTruststore)),
			"metadataSigningTruststorePassword": []byte(metadataSigningTruststorePassword),
			// "signing.crt":                  samlSigningCert,
			// "signing.truststore":           samlSigningTruststore,
			// "signingTruststorePassword":    samlSigningTruststorePassword,
			// "signgingKeyLabel":             samlSigningKeyLabel,
			// "encryption.crt":               samlEncyptionCert,
			// "encryption.truststore":        samlEncryptionTruststore,
			// "encryptionTruststorePassword": samlEncryptionTruststorePassword,
			// "encryptionKeyLabel":           samlEncryptionKeyLabel,
		},
	}
	if err := controllerutil.SetControllerReference(instance, metadataConfigMap, r.scheme); err != nil {
		return reconcile.Result{}, err
	}
	// Find or create metadataConfigMap
	foundConfigMap := &corev1.ConfigMap{}
	err = r.Get(context.TODO(), types.NamespacedName{Name: metadataConfigMap.Name, Namespace: metadataConfigMap.Namespace}, foundConfigMap)
	if err != nil && errors.IsNotFound(err) {
		log.Info("Creating ConfigMap", "namespace", metadataConfigMap.Namespace, "name", metadataConfigMap.Name)
		err = r.Create(context.TODO(), metadataConfigMap)
		if err != nil {
			return reconcile.Result{}, err
		}
	} else if err != nil {
		return reconcile.Result{}, err
	} else {
		// Update the found object and write the result back if there are any changes
		if !reflect.DeepEqual(metadataConfigMap.BinaryData, foundConfigMap.BinaryData) {
			foundConfigMap.BinaryData = metadataConfigMap.BinaryData
			log.Info("Updating ConfigMap", "namespace", metadataConfigMap.Namespace, "name", metadataConfigMap.Name)
			err = r.Update(context.TODO(), foundConfigMap)
			if err != nil {
				return reconcile.Result{}, err
			}
		}
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
									MountPath: "/usr/share/nginx/html",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "data",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{Name: metadataConfigMap.Name},
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
			return reconcile.Result{}, err
		}
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Update the found object and write the result back if there are any changes
	if !reflect.DeepEqual(metadataDeployment.Spec, foundDeployment.Spec) {
		foundDeployment.Spec = metadataDeployment.Spec
		log.Info("Updating Deployment", "namespace", metadataDeployment.Namespace, "name", metadataDeployment.Name)
		err = r.Update(context.TODO(), foundDeployment)
		if err != nil {
			return reconcile.Result{}, err
		}
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
			return reconcile.Result{}, err
		}
	} else if err != nil {
		return reconcile.Result{}, err
	}
	// Update the found object and write the result back if there are any changes
	if !reflect.DeepEqual(metadataService.Spec, foundService.Spec) {
		foundService.Spec = metadataService.Spec
		log.Info("Updating Service", "namespace", metadataService.Namespace, "name", metadataService.Name)
		err = r.Update(context.TODO(), foundService)
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	return reconcile.Result{}, nil
}

func createTruststore(cert []byte, storePass string) ([]byte, error) {
	exe, err := exec.LookPath("keytool")
	if err != nil {
		return nil, err
	}
	tmpDir, err := ioutil.TempDir("", "createTruststore")
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
	cmd := exec.Command(exe,
		"-import",
		"-noprompt",
		"-trustcacerts",
		"-alias", "cert",
		"-storepass", storePass,
		"-keystore", tmpTruststorePath,
		"-file", tmpCertPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute mdgen: %s", out)
	}
	b, err := ioutil.ReadFile(tmpTruststorePath)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func generateAndSignMetadata(metadataSigningCertPath string, metadataSigningKeyLabel string, spec verifyv1beta1.MetadataSpec) (signedMetadata []byte, err error) {
	specFileName, err := createGeneratorFile(spec.Data)
	defer os.Remove(specFileName)
	if err != nil {
		return nil, err
	}

	metadataFile, err := ioutil.TempFile("", "metadata")
	defer metadataFile.Close()
	defer os.Remove(metadataFile.Name())

	log.Info("Generating metadata", "specFileName", specFileName,
		"metadataFileName", metadataFile.Name())
	cmd := exec.Command("/mdgen/build/install/mdgen/bin/mdgen", spec.Type,
		specFileName, metadataSigningCertPath,
		"--output", metadataFile.Name(),
		"--algorithm", "rsa",
		"--credential", "cloudhsm",
		"--hsm-key-label", metadataSigningKeyLabel)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute mdgen: %s", out)
	}

	metadataBytes, err := ioutil.ReadFile(metadataFile.Name())
	if err != nil {
		return nil, err
	}
	if len(metadataBytes) == 0 {
		return nil, fmt.Errorf("no metadata generated from mdgen: %s", out)
	}

	log.Info("Generated metadata", "metadata", string(metadataBytes))
	return metadataBytes, nil
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
