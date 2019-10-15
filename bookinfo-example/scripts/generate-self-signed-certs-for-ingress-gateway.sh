#!/usr/bin/env bash

set -eu

ingress_host=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# Generate certs using openssl
openssl req -outform PEM -out /tmp/key.crt.pem -new -keyout /tmp/key.pem -newkey rsa:2048 -batch -nodes -x509 -subj "/CN=${ingress_host}" -days 365

# upload the certs by creating a k8s secret
kubectl create -n istio-system secret tls istio-ingressgateway-certs --key /tmp/key.pem --cert /tmp/key.crt.pem

# make sure the secret is correctly created
echo; echo; echo "Verify that the secret is created:"
kubectl get secret --all-namespaces | grep istio-ingressgateway-certs
