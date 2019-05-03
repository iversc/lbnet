@echo off

cd /D %~dp0

certutil -delstore -user Root "AAA__DO_NOT_TRUST_Test Root CA"
certutil -delstore -user CA "AAA_DO_NOT_TRUST_Test Sub CA"
certutil -delstore -user My localhost

pause