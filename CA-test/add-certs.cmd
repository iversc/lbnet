@echo off

cd /D %~dp0

certutil -addstore Root root-ca\certs\root-ca.crt

certutil -addstore CA sub-ca\certs\sub-ca.crt

certutil -ImportPFX -p "" localhost\localhost.pfx

pause