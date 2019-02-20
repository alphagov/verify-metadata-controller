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

// MetadataSpec defines the desired state of Metadata
type MetadataSpec struct {
	ID                   string `json:"id,omitempty"`
	EntityID             string `json:"entity_id"`
	PostURL              string `json:"post_url"`
	RedirectURL          string `json:"redirect_url"`
	OrgName              string `json:"org_name"`
	OrgDisplayName       string `json:"org_display_name"`
	OrgURL               string `json:"org_url"`
	ContactCompany       string `json:"contact_company"`
	ContactGivenName     string `json:"contact_given_name"`
	ContactSurname       string `json:"contact_surname"`
	ContactEmail         string `json:"contact_email"`
	Enabled              bool   `json:"enabled,omitempty"`
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
