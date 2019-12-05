#!/usr/bin/env bash

set -eux

script_dir=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd ${script_dir}/../istio-1.4.0

# Follow quick setup instructions for Istio
for i in install/kubernetes/helm/istio-init/files/crd*yaml; do
  kubectl apply -f ${i};
done

# For testing purposes, we’ll go the with “permissive mtls” setup
kubectl apply -f install/kubernetes/istio-demo.yaml

# Wait until all the istio components are running
while true; do
    kubectl get pods -n istio-system
    echo
    read -p "Are all of the pods completed/running? (y/n)" yn
    case ${yn} in
        [Yy]* ) break;;
        [Nn]* ) ;;
        * ) echo "Please answer yes or no.";;
    esac
done

# Label the namespace in which you intend to deploy your app to enable automatic
# sidecar injection for all pods in that namespace. E.g. if you plan to deploy
# your app into the default namespace:
kubectl label namespace default istio-injection=enabled
