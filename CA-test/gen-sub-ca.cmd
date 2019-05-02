@echo off
call OpenSSL-ENV.cmd

mkdir sub-ca
mkdir sub-ca\certs sub-ca\crl sub-ca\newcerts sub-ca\private sub-ca\csr
type nul >> sub-ca\index.txt
echo 1000 > sub-ca\serial

openssl genrsa -out sub-ca\private\sub-ca.key 4096

openssl req -new -config sub-ca.conf -key sub-ca\private\sub-ca.key -out sub-ca\csr\sub-ca.csr

openssl ca -batch -config root-ca.conf -in sub-ca\csr\sub-ca.csr -out sub-ca\certs\sub-ca.crt -extensions v3_intermediate_ca 
