@echo off
call gen-root-ca.cmd
call gen-sub-ca.cmd
call gen-localhost-cert.cmd
