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
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	verifyv1beta1 "github.com/alphagov/verify-metadata-controller/pkg/apis/verify/v1beta1"
	"github.com/alphagov/verify-metadata-controller/pkg/hsm"
	"github.com/mitchellh/hashstructure"
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

const (
	cloudHSMKeyType    = "cloudhsm"
	metadataXMLKey     = "metadata.xml"
	metadataCACertsKey = "metadataCACerts"
	truststorePassword = "mashmallow"
	versionAnnotation  = "metadata-version"
	validityDays       = "validityDays"
	validUntil         = "validUntil"
	beginTag           = "-----BEGIN CERTIFICATE-----\n"
	endTag             = "\n-----END CERTIFICATE-----"
	requeueAfterNS     = 1800000000000
)

var log = logf.Log.WithName("controller")

// Add creates a new Metadata Controller and adds it to the Manager with default RBAC. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager, hsmClient hsm.Client) error {
	return AddReconciler(mgr, NewReconciler(mgr, hsmClient))
}

// NewReconciler returns a new reconcile.Reconciler
func NewReconciler(mgr manager.Manager, hsmClient hsm.Client) reconcile.Reconciler {
	return &ReconcileMetadata{
		Client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		hsm:    hsmClient,
	}
}

// AddReconciler adds a new Controller to mgr with r as the reconcile.Reconciler
func AddReconciler(mgr manager.Manager, r reconcile.Reconciler) error {
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

func (r *ReconcileMetadata) getCACerts(ctx context.Context, name, namespace string) ([][]byte, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, secret)
	if err != nil && errors.IsNotFound(err) {
		return nil, fmt.Errorf("getCACerts: failed to get Secret %s in namespace %s", name, namespace)
	} else if err != nil {
		return nil, fmt.Errorf("getCACerts: failed to get Secret %s in namespace %s: %s", name, namespace, err)
	}
	cert := secret.Data["cert"]
	if cert == nil {
		return nil, fmt.Errorf("getCACerts: no 'cert' value in Secret %s in namespace %s", name, namespace)
	}
	certs := [][]byte{cert}
	certRequest := &verifyv1beta1.CertificateRequest{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}, certRequest)
	if err != nil && errors.IsNotFound(err) {
		return nil, fmt.Errorf("getCACerts: failed to get CertificateRequest %s in namespace %s", name, namespace)
	} else if err != nil {
		return nil, fmt.Errorf("getCACerts: failed to get CertificateRequest %s in namespace %s: %s", name, namespace, err)
	}
	if certRequest.Spec.CertificateAuthority != nil {
		parentCerts, err := r.getCACerts(
			ctx,
			certRequest.Spec.CertificateAuthority.SecretName,
			certRequest.Spec.CertificateAuthority.Namespace,
		)
		if err != nil {
			return nil, fmt.Errorf("getCACerts: failed to call getCACerts: %s", err)
		}
		certs = append(certs, parentCerts...)
	}
	return certs, nil
}

func (r *ReconcileMetadata) generateMetadataSecretData(instance *verifyv1beta1.Metadata, metadataSigningSecret *corev1.Secret, ca *verifyv1beta1.CertificateAuthoritySpec) (map[string][]byte, error) {

	if instance.Spec.SAMLSigningCertificate == nil {
		if instance.Spec.Data.SamlEncryptionCertificate == "" || instance.Spec.Data.SamlSigningCertificate == "" {
			return nil, fmt.Errorf("encryption and signing certs are required if CertificateSigningRequest is absent")
		}
	}
	if metadataSigningSecret == nil {
		return nil, fmt.Errorf("metadataSigningSecret is required")
	}
	metadataHSMUser := metadataSigningSecret.Data["hsmUser"]
	if metadataHSMUser == nil {
		return nil, fmt.Errorf("no 'hsmUser' value in CA secret '%s'", metadataSigningSecret.ObjectMeta.Name)
	}
	metadataHSMPassword := metadataSigningSecret.Data["hsmPassword"]
	if metadataHSMPassword == nil {
		return nil, fmt.Errorf("no 'hsmPassword' value in CA secret '%s'", metadataSigningSecret.ObjectMeta.Name)
	}
	metadataHSMIP := metadataSigningSecret.Data["hsmIP"]
	if metadataHSMIP == nil {
		return nil, fmt.Errorf("no 'hsmIP' value in CA secret '%s'", metadataSigningSecret.ObjectMeta.Name)
	}
	metadataHSMCustomerCA := metadataSigningSecret.Data["hsmCustomerCA"]
	if metadataHSMCustomerCA == nil {
		return nil, fmt.Errorf("no 'hsmCustomerCA' value in CA secret '%s'", metadataSigningSecret.ObjectMeta.Name)
	}
	metadataSigningCert := metadataSigningSecret.Data["cert"]
	if metadataSigningCert == nil {
		return nil, fmt.Errorf("no 'cert' value in metadataSigningSecret '%s'", metadataSigningSecret.ObjectMeta.Name)
	}
	metadataSigningKeyLabel := metadataSigningSecret.Data["label"]
	if metadataSigningKeyLabel == nil {
		return nil, fmt.Errorf("no 'label' value in metadataSigningSecret '%s'", metadataSigningSecret.ObjectMeta.Name)
	}
	metadataSigningTruststore, err := generateTruststore(metadataSigningCert, string(metadataSigningKeyLabel), truststorePassword, instance)
	if err != nil {
		return nil, err
	}

	// generate ca chain data
	if ca == nil {
		return nil, fmt.Errorf("did not expect 'ca' to be nil")
	}
	metadataCACerts, err := r.getCACerts(context.TODO(), ca.SecretName, ca.Namespace)
	if err != nil {
		return nil, fmt.Errorf("generateMetadataSecretData: %s", err)
	}
	var metadataCACertsConcat []byte
	if len(metadataCACerts) > 1 {
		metadataCACertsConcat = bytes.Join(metadataCACerts[1:], []byte("\n"))
	} else {
		metadataCACertsConcat = metadataCACerts[0]
	}

	metadataCATruststore, err := generateTruststore(metadataCACertsConcat, "ca", truststorePassword, instance)
	if err != nil {
		return nil, err
	}
	metadataCATruststorePassword := truststorePassword

	samlSigningKeyLabel := fmt.Sprintf("%s-%s-saml", instance.ObjectMeta.Namespace, instance.ObjectMeta.Name)
	var samlSigningCert []byte
	var samlEncryptionCert []byte
	var samlSigningCreds hsm.Credentials

	signingCertFromCertRequest := instance.Spec.SAMLSigningCertificate != nil

	if signingCertFromCertRequest {
		// generate samlSigningCert and key
		samlSigningCreds, err = hsm.GetCredentials()
		if err != nil {
			return nil, err
		}
		_, err = r.hsm.FindOrCreateRSAKeyPair(samlSigningKeyLabel, samlSigningCreds)
		if err != nil {
			return nil, fmt.Errorf("findOrCreateRSAKeyPair(%s): %s", samlSigningKeyLabel, err)
		}
		samlSigningCertReq := hsm.CertRequest{
			CountryCode:      instance.Spec.SAMLSigningCertificate.CountryCode,
			CommonName:       instance.Spec.SAMLSigningCertificate.CommonName,
			ExpiryMonths:     instance.Spec.SAMLSigningCertificate.ExpiryMonths,
			Location:         instance.Spec.SAMLSigningCertificate.Location,
			Organization:     instance.Spec.SAMLSigningCertificate.Organization,
			OrganizationUnit: instance.Spec.SAMLSigningCertificate.OrganizationUnit,
		}
		samlSigningCert, err = r.hsm.CreateSelfSignedCert(samlSigningKeyLabel, samlSigningCreds, samlSigningCertReq)
		if err != nil {
			return nil, fmt.Errorf("CreateSelfSignedCert(%s): %s", samlSigningKeyLabel, err)
		}
		samlEncryptionCert = samlSigningCert
	} else {
		samlSigningCert = formatCertString(instance.Spec.Data.SamlSigningCertificate)
		samlEncryptionCert = formatCertString(instance.Spec.Data.SamlEncryptionCertificate)
	}

	// TODO do we need this truststore? If so, do we need an encryption one?
	samlSigningTruststore, err := generateTruststore(samlSigningCert, samlSigningKeyLabel, truststorePassword, instance)
	if err != nil {
		return nil, err
	}
	samlSigningTruststorePassword := truststorePassword

	metadataValidityDays := instance.Spec.Data.ValidityDays
	if metadataValidityDays == 0 {
		metadataValidityDays = 30
	}

	metadataExpiryDatetime := time.Now().AddDate(0, 0, metadataValidityDays)
	metadataExpiryTimestamp := metadataExpiryDatetime.Format(time.RFC1123Z)

	metadataRequest := hsm.GenerateMetadataRequest{
		MetadataSigningCert:     metadataSigningCert,
		SAMLSigningCert:         samlSigningCert,
		SAMLEncryptionCert:      samlEncryptionCert,
		MetadataSigningKeyLabel: string(metadataSigningKeyLabel),
		SamlSigningKeyLabel:     string(samlSigningKeyLabel),
		HSMSAMLSigning:          signingCertFromCertRequest,
		HSMCreds: hsm.Credentials{
			IP:         string(metadataHSMIP),
			User:       string(metadataHSMUser),
			Password:   string(metadataHSMPassword),
			CustomerCA: string(metadataHSMCustomerCA),
		},
		Type: instance.Spec.Type,
		Data: hsm.MetadataRequestData{
			EntityID:          instance.Spec.Data.EntityID,
			PostURL:           instance.Spec.Data.PostURL,
			RedirectURL:       instance.Spec.Data.RedirectURL,
			OrgName:           instance.Spec.Data.OrgName,
			OrgDisplayName:    instance.Spec.Data.OrgDisplayName,
			OrgURL:            instance.Spec.Data.OrgURL,
			ContactCompany:    instance.Spec.Data.ContactCompany,
			ContactGivenName:  instance.Spec.Data.ContactGivenName,
			ContactSurname:    instance.Spec.Data.ContactSurname,
			ContactEmail:      instance.Spec.Data.ContactEmail,
			ValidityTimestamp: metadataExpiryTimestamp,
		},
	}
	signedMetadata, err := r.hsm.GenerateAndSignMetadata(metadataRequest)
	if err != nil {
		return nil, fmt.Errorf("generateAndSignMetadata(%s): %s", metadataSigningKeyLabel, err)
	}

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
		metadataCACertsKey:                  []byte(metadataCACertsConcat),
		"metadataCATruststore":              []byte(metadataCATruststore),
		"metadataCATruststoreBase64":        []byte(base64.StdEncoding.EncodeToString(metadataCATruststore)),
		"metadataCATruststorePassword":      []byte(metadataCATruststorePassword),
		"publishingPath":                    []byte(getPublishingPath(instance)),
		"samlSigningCert":                   []byte(samlSigningCert),
		"samlSigningCertBase64":             []byte(base64.StdEncoding.EncodeToString(samlSigningCert)),
		"samlSigningTruststore":             []byte(samlSigningTruststore),
		"samlSigningTruststoreBase64":       []byte(base64.StdEncoding.EncodeToString(samlSigningTruststore)),
		"samlSigningTruststorePassword":     []byte(samlSigningTruststorePassword),
		"samlSigningKeyType":                []byte(cloudHSMKeyType),
		"samlSigningKeyLabel":               []byte(samlSigningKeyLabel),
		"samlEncryptionCert":                []byte(samlEncryptionCert),
		validityDays:                        []byte(strconv.Itoa(metadataValidityDays)),
		validUntil:                          []byte(metadataExpiryTimestamp),
	}

	if signingCertFromCertRequest {
		data["hsmUser"] = []byte(samlSigningCreds.User)
		data["hsmPassword"] = []byte(samlSigningCreds.Password)
		data["hsmIP"] = []byte(samlSigningCreds.IP)
		data["hsmCIDR"] = []byte(fmt.Sprintf("%s/32", samlSigningCreds.IP))
		data["hsmCustomerCA.crt"] = []byte(samlSigningCreds.CustomerCA)
	}

	return data, nil
}

// This function determines if we should regenerate the metadata or not.
func ShouldRegenerate(secretsObj *corev1.Secret, hashOfRequestSpec string, instance verifyv1beta1.Metadata) bool {
	logInfo("Checking if metadata secret should be regenerated", instance.ObjectMeta)
	secretsMap := secretsObj.Data

	// If the rest of the config has changed and the hash has changed, regenerate regardless.
	if secretsObj.ObjectMeta.Annotations[versionAnnotation] != hashOfRequestSpec {
		logInfo("Regenerating secret - hashes don't match", instance.ObjectMeta)
		return true
	}

	// Checking the date from the secrets store to see if we need to regenerate the metadata.
	byteValidityDays := secretsMap[validityDays]
	byteValidUntil := secretsMap[validUntil]

	// If there's nothing in the map then regenerate metadata.
	if byteValidityDays == nil || byteValidUntil == nil {
		logInfo(fmt.Sprintf("Regenerating secret - either validityDays %q or validUntil %q are nil", byteValidityDays, byteValidUntil), instance.ObjectMeta)
		return true
	}

	intValidityDays, errValidityDays := strconv.Atoi(string(byteValidityDays))
	validUntilTimeStamp, errValidUntil := time.Parse(time.RFC1123Z, string(byteValidUntil))

	if errValidUntil != nil || errValidityDays != nil {
		logInfo(fmt.Sprintf("Regenerating secret - unable to parse validityDays %q or validUntil %q", errValidityDays, errValidUntil), instance.ObjectMeta)
		return true
	}

	// We want to regenerate the metadata if it's at least halfway through its lifetime.
	regeneratePastThisDate := time.Now().Add(time.Hour * time.Duration(12*intValidityDays))

	// If the timestamp is less than half the metadata's lifetime away then regenerate it.
	regenerate := validUntilTimeStamp.Before(regeneratePastThisDate)
	logInfo(fmt.Sprintf("Regenerating secret %t - validUntilTimeStamp %q not before regeneratePastThisDate %q", regenerate, validUntilTimeStamp, regeneratePastThisDate), instance.ObjectMeta)
	return regenerate
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
			logInfoRequest("Metadata reconcile failed - object not found", request)
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		logInfoRequest("Metadata reconcile failed - error reading object", request, "error", err)
		return reconcile.Result{}, err
	}

	logInfo("Beginning Reconcile for metadata", instance.ObjectMeta)

	// Generate a hash of the metadata values
	currentVersionInt, err := hashstructure.Hash(instance.Spec, nil)
	if err != nil {
		return reconcile.Result{}, err
	}
	currentVersion := fmt.Sprintf("%d", currentVersionInt)
	logInfo("Hash of metadata values", instance.ObjectMeta, "hashValue", currentVersion)

	// lookup certificate authority data
	metadataSigningSecret := &corev1.Secret{}
	err = r.Get(context.TODO(), types.NamespacedName{
		Name:      instance.Spec.CertificateAuthority.SecretName,
		Namespace: instance.Spec.CertificateAuthority.Namespace,
	}, metadataSigningSecret)
	if err != nil && errors.IsNotFound(err) {
		return reconcile.Result{}, fmt.Errorf("certificateAuthority Secret '%s' not found in namespace '%s'", instance.Spec.CertificateAuthority.SecretName, instance.Spec.CertificateAuthority.Namespace)
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("certificateAuthority Secret '%s' in namespace '%s': %s", instance.Spec.CertificateAuthority.SecretName, instance.Spec.CertificateAuthority.Namespace, err)
	}

	// Find or create metadataSecret
	foundSecret := &corev1.Secret{}
	err = r.Get(context.TODO(), types.NamespacedName{
		Name:      instance.Name,
		Namespace: instance.Namespace,
	}, foundSecret)
	if err != nil && errors.IsNotFound(err) {
		logInfo("Creating metadata secret (secret was not found)", instance.ObjectMeta, "version", currentVersion)
		metadataSecretData, err := r.generateMetadataSecretData(instance, metadataSigningSecret, &instance.Spec.CertificateAuthority)
		if err != nil {
			return reconcile.Result{}, err
		}
		metadataSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      instance.Name,
				Namespace: instance.Namespace,
				Annotations: map[string]string{
					versionAnnotation: currentVersion,
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
		logInfo("Created metadata secret", metadataSecret.ObjectMeta, "version", currentVersion)
	} else if err != nil {
		return reconcile.Result{}, err
	} else if ShouldRegenerate(foundSecret, currentVersion, *instance) {
		logInfo("Updating metadata secret", foundSecret.ObjectMeta, "version", foundSecret.ObjectMeta.Annotations[versionAnnotation])
		updatedData, err := r.generateMetadataSecretData(instance, metadataSigningSecret, &instance.Spec.CertificateAuthority)
		if err != nil {
			return reconcile.Result{}, err
		}
		foundSecret.ObjectMeta.Annotations[versionAnnotation] = currentVersion
		foundSecret.Data = updatedData
		err = r.Update(context.TODO(), foundSecret)
		if err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to update Secret %s: %s", foundSecret.ObjectMeta.Name, err)
		}
		logInfo("Updated metadata secret", foundSecret.ObjectMeta, "version", currentVersion)
	} else {
		logInfo("Metadata up-to-date, not regenerating at this time", instance.ObjectMeta)
	}

	logInfo(fmt.Sprintf("Instance reconciliation complete - requeuing in %d seconds (%d minutes)",
		requeueAfterNS/1000000000, requeueAfterNS/1000000000/60), instance.ObjectMeta)
	return reconcile.Result{RequeueAfter: requeueAfterNS}, nil
}

func generateTruststore(cert []byte, alias, storePass string, instance *verifyv1beta1.Metadata) ([]byte, error) {
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
	logInfo("Generating truststore", instance.ObjectMeta, "alias", alias)
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

func getPublishingPath(instance *verifyv1beta1.Metadata) string {
	if instance.Spec.PublishingPath != "" {
		return instance.Spec.PublishingPath
	} else {
		return metadataXMLKey
	}
}


func formatCertString(certString string) []byte {
	return []byte(beginTag + certString + endTag)
}

func logInfo(msg string, metadata metav1.ObjectMeta, additionalKeysAndValues ...interface{}) {
	log.Info(msg, append(additionalKeysAndValues, "namespace", metadata.Namespace, "name", metadata.Name)...)
}

func logInfoRequest(msg string, request reconcile.Request, additionalKeysAndValues ...interface{}) {
	log.Info(msg, append(additionalKeysAndValues, "namespace", request.Namespace, "name", request.Name)...)
}
