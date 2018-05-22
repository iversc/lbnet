#pragma once

#define MESOCK32_API EXTERN_C __declspec(dllimport)
typedef ULONG Mesock32Socket;
typedef int Mesock32Ret;

MESOCK32_API int Send(Mesock32Socket sock, PVOID msg);
MESOCK32_API PVOID Receive(Mesock32Socket sock, int BytesToRead, int ReadAll);