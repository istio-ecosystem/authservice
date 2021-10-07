#!/usr/bin/env bash

set -eu

# Generate certs using openssl
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
 -days 365 -nodes -subj '/CN=localhost'

# upload the certs by creating a k8s secret
kubectl create -n istio-system secret tls ingress-tls-cert --key=key.pem \
  --cert=cert.pem

# make sure the secret is correctly created
echo; echo; echo "Verify that the secret is created:"
kubectl get secret -nistio-system | grep ingress-tls-cert
