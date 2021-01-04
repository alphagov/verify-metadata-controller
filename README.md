# verify-metadata-controller

## Overview

Kubernetes Custom Resource and Controller for generating and signing SAML metadata

## Requirements

- [docker](https://www.docker.com/)
- [minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/)
- [kubebuilder](https://book.kubebuilder.io/quick-start.html#installation)
- [kustomize](https://github.com/kubernetes-sigs/kustomize/blob/master/docs/INSTALL.md)
- [gds-cli](https://github.com/alphagov/gds-cli)
- [dep](https://github.com/golang/dep)
- [counterfeiter](github.com/maxbrunsfeld/counterfeiter)

## Development

Use `gds-cli` to update `kubeconfig` to refer to the target cluster:

`gds-cli <cluster e.g. (verify|sandbox)> update-kubeconfig`

This will generate a `kubeconfig` in `~/.gds/<cluster>-<cluster>.kubeconfig`

Export this config:
`export KUBECONFIG=~/.gds/<cluster>-<cluster>.kubeconfig`
---
To build and deploy to a development environment:

```
eval $(minikube docker-env)     # point local docker commands at the engine in minikube
make                            # regenerate controller/api after changes
make docker-build               # build the controller image
make deploy                     # install controller with kubectl
```

```
kubectl delete pod/verify-metadata-controller-controller-manager-0
```

To get the project to run and build you need to place it under your `$GOROOT` which is typically set to `~/go/src/` the path for the project should look something like `~/go/src/github.com/alphagov/verify-metadata-controller`.

Once you have dep installed you should be able to run `dep ensure` from the root of the project.
Followed by `go get -u github.com/maxbrunsfeld/counterfeiter` this should be enough to get the project running.
Simply now run `make` and see if it explodes.

## Controller Unit Tests

The controller unit tests (Go) require a kubernetes control plane to function, the kubebuilder tools provide this.

The easist way to run the tests is to use Docker:

```
docker build -f Docker.test .
```

## Deployment Test

To build and deploy to a local Docker-in-Docker cluster (DinD) Run

```
./hack/test.sh
```

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
    /opt/cloudhsm/bin/configure -a $(dig +short afe8ce8bf61fb11eaa69a0af1fbe14c4-afb9ba656e22f14e.elb.eu-west-2.amazonaws.com | head -n 1)
    ```
1. Test the connection by listing users:
    ```
    /opt/cloudhsm/bin/cloudhsm_mgmt_util /opt/cloudhsm/etc/cloudhsm_mgmt_util.cfg
    listUsers
    ```
