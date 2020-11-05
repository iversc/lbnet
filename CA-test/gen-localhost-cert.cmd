@echo off

call OpenSSL-ENV.cmd

mkdir localhost

openssl genrsa -out localhost\localhost.key

openssl req -new -config localhost.conf -key localhost\localhost.key -out localhost\localhost.csr

openssl ca -batch -config sub-ca.conf -in localhost\localhost.csr -out localhost\localhost.crt -extensions server_cert

openssl pkcs12 -export -in localhost\localhost.crt -out localhost\localhost.pfx -inkey localhost\localhost.key -CAfile sub-ca\certs\chain.pem -chain -passout pass:

openssl pkcs12 -export -in localhost\localhost.crt -out localhost\localhost-test.pfx -inkey localhost\localhost.key -CAfile sub-ca\certs\chain.pem -chain -passout pass:test