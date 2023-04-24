#!/bin/bash

# Create the CA
mkdir demoCA

cd demoCA

mkdir certs crl newcerts

touch index.txt serial

echo 1000 > serial

cd ..

cp /usr/lib/ssl/openssl.cnf myCA_openssl.cnf

# Genereate the certificates

openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -keyout ca.key -out ca.crt -subj "/CN=www.modelCA.com/O=Model CA LTD./C=US/ST=New York/L=Syracuse" -passout pass:dees

openssl req -newkey rsa:2048 -sha256 -keyout vpn.key -out vpn.csr -subj "/CN=vpnlabserver.com/O=Model CA LTD./C=US/ST=New York/L=Syracuse" -passout pass:dees

openssl ca -config myCA_openssl.cnf -policy policy_anything -md sha256 -days 3650 -in vpn.csr -out vpn.crt -batch -cert ca.crt -keyfile ca.key

openssl x509 -in ca.crt -noout -subject_hash
# it should output the following
# > eaa14a05

ln -s ca.crt eaa14a05.0