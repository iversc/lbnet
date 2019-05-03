@echo off

cd /D %~dp0

certutil -delstore Root "AAA__DO_NOT_TRUST_Test Root CA"
certutil -delstore CA "AAA_DO_NOT_TRUST_Test Sub CA"
certutil -delstore My localhost

pause