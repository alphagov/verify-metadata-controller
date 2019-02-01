#!/usr/bin/env bash

set -eu # 🇪🇺

export NUM_NODES=1
export IMG=metadata-controller:latest

kubectl get nodes || ./hack/dind-cluster.sh up

kubectl delete pods,deployment --all

make
make docker-build
./hack/dind-cluster.sh copy-image "${IMG}"
make deploy

kubectl apply -f config/samples/verify_v1beta1_metadata.yaml

sleep 3

kubectl port-forward service/metadata-sample 8080:80 &
trap "kill %1" EXIT

sleep 1

(curl http://localhost:8080/metadata.xml | tee | grep "https://example-gateway.verify.govsvc.uk/") || (echo 'FAILED' && exit 1)
