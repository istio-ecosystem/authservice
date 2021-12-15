#!/bin/bash

openssl genrsa 2048 > tls.key
openssl req -new -key tls.key -subj "/C=JP/ST=Kanagawa/L=Aoba/O=Shikugawa/CN=shikugawa.net" > tls.csr
openssl x509 -days 3650 -req -extfile ext.txt -signkey tls.key < tls.csr > tls.crt
