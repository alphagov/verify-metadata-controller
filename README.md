# verify-metadata-controller

## Overview

Kubernetes Custom Resource and Controller for generating and signing SAML metadata

## Development

```
eval $(minikibe docker-env)     # point local docker commands at the engine in minikube 
make                            # regenerate controller/api after changes
make docker-build               # build the controller image
make deploy                     # install controller with kubectl 
```

```
kubectl delete -n verify-metadata-controller-system pod/verify-metadata-controller-controller-manager-0
```

