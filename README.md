# verify-metadata-controller

## Overview

Kubernetes Custom Resource and Controller for generating and signing SAML metadata

## Requirements

- docker
- [kubebuilder](https://book.kubebuilder.io/getting_started/installation_and_setup.html)
- [kustomize](https://github.com/kubernetes-sigs/kustomize/blob/master/docs/INSTALL.md)

## Development

```
eval $(minikibe docker-env)     # point local docker commands at the engine in minikube 
make                            # regenerate controller/api after changes
make docker-build               # build the controller image
make deploy                     # install controller with kubectl 
```

```
kubectl delete pod/verify-metadata-controller-controller-manager-0
```

## Test

Run `./hack/test.sh`
