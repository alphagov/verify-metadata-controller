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

// SigningSpec provides the details for the metadata generator and signer
// +k8s:openapi-gen=true
type MetadataSigningSpec struct {
	EntityID              string `json:"entityID,omitempty"`
	PostURL               string `json:"postURL,omitempty"`
	RedirectURL           string `json:"redirectURL,omitempty"`
	OrgName               string `json:"orgName,omitempty"`
	OrgDisplayName        string `json:"orgDisplayName,omitempty"`
	OrgURL                string `json:"orgURL,omitempty"`
	ContactCompany        string `json:"contactCompany,omitempty"`
	ContactGivenName      string `json:"contactGivenName,omitempty"`
	ContactSurname        string `json:"contactSurname,omitempty"`
	ContactEmail          string `json:"contactEmail,omitempty"`
	SigningCertificate    string `json:"signingCertificate,omitempty"`
	EncryptionCertificate string `json:"encryptionCertificate,omitempty"`
}

// MetadataSpec defines the desired state of Metadata
// +k8s:openapi-gen=true
type MetadataSpec struct {
	ID                     string                   `json:"id,omitempty"`
	Type                   string                   `json:"type"`
	Data                   MetadataSigningSpec      `json:"data,omitempty"`
	Enabled                bool                     `json:"enabled,omitempty"`
	CertificateAuthority   CertificateAuthoritySpec `json:"certificateAuthority"`
	SAMLSigningCertificate *CertificateRequestSpec  `json:"samlSigningCertRequest,omitempty"`
}

// MetadataStatus defines the observed state of Metadata
type MetadataStatus struct {
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Metadata is the Schema for the metadata API
// +k8s:openapi-gen=true
type Metadata struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MetadataSpec   `json:"spec,omitempty"`
	Status MetadataStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MetadataList contains a list of Metadata
type MetadataList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Metadata `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Metadata{}, &MetadataList{})
}
