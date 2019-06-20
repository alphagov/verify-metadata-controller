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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CertificateRequestSpec defines the desired state of CertificateRequest
// +k8s:openapi-gen=true
type CertificateRequestSpec struct {
	CountryCode          string `json:"countryCode,omitempty"`
	CommonName           string `json:"commonName"`
	ExpiryMonths         int    `json:"expiryMonths,omitempty"`
	Location             string `json:"location,omitempty"`
	Organization         string `json:"organization,omitempty"`
	OrganizationUnit     string `json:"organizationUnit,omitempty"`
	ParentCertSecretName string `json:"parentCertSecretName,omitempty"`
	ParentCertNamespace  string `json:"parentCertNamespace,omitempty"`
	CACert               bool   `json:"caCert,omitempty"`
}

// CertificateRequestStatus defines the observed state of CertificateRequest
type CertificateRequestStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// CertificateRequest is the Schema for the certificaterequests API
// +k8s:openapi-gen=true
type CertificateRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateRequestSpec   `json:"spec,omitempty"`
	Status CertificateRequestStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// CertificateRequestList contains a list of CertificateRequest
type CertificateRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CertificateRequest `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CertificateRequest{}, &CertificateRequestList{})
}
