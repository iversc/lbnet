@echo off

cd /D %~dp0

certutil -addstore -user Root root-ca\certs\root-ca.crt

certutil -addstore -user CA sub-ca\certs\sub-ca.crt

certutil -ImportPFX -user -p "" localhost\localhost.pfx

pause