@echo off
call OpenSSL-ENV.cmd

mkdir root-ca
mkdir root-ca\certs root-ca\crl root-ca\newcerts root-ca\private
type nul >> root-ca\index.txt
echo 1000 > root-ca\serial

openssl genrsa -out root-ca\private\root-ca.key 4096

openssl req -new -config root-ca.conf -key root-ca\private\root-ca.key -x509 -days 7300 -sha256 -extensions v3_ca -out root-ca\certs\root-ca.crt

