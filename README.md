# verify-metadata-controller

## Overview

Kubernetes Custom Resource and Controller for generating and signing SAML metadata

## Requirements

- docker
- [kubebuilder](https://book.kubebuilder.io/quick-start.html#installation)
- [kustomize](https://github.com/kubernetes-sigs/kustomize/blob/master/docs/INSTALL.md)
- [gds-cli](https://github.com/alphagov/gds-cli)

## Development

Use `gds-cli` to update `kubeconfig` to refer to the target cluster:    

`gds-cli <cluster> update-kubeconfig`

This will generate a `kubeconfig` in `~/.gds/<cluster>-<cluster>.kubeconfig`

Export this config:
`exportKUBECONFIG=~/.gds/<cluster>-<cluster>.kubeconfig`
---
To build and deploy to a development environment:

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

## Connecting to Sandbox CloudHSM for local development

Note: Access to the Sandbox environments CloudHSM is only possible from a GDS IP.

1. Get Sandbox CloudHSM Certificate:
    ```
    aws-vault exec run-sandbox -- kubectl get secrets -n sandbox-metadata-controller -o yaml vmc | grep customerCA.crt | sed "s/  customerCA.crt: //1" | base64 -D >> $(pwd)/sandbox-customerCA.crt
    ```
1. Startup a docker container and mount the certificate:
    ```
    docker run -it -v $(pwd)/sandbox-customerCA.crt:/opt/cloudhsm/etc/customerCA.crt --rm govsvc/cloudhsm-client-test:0.0.1560968513 bash
    ```
1. Configure CloudHSM Client:
    ```
    apt-get install dnsutils -y
    /opt/cloudhsm/bin/configure -a $(dig +short a88bb4c07943b11e9bbf30ae9bf7a1ac-aa921f50a00f6c2a.elb.eu-west-2.amazonaws.com)
    ```
1. Test the connection by listing users:
    ```
    /opt/cloudhsm/bin/cloudhsm_mgmt_util /opt/cloudhsm/etc/cloudhsm_mgmt_util.cfg
    listUsers
    ```
