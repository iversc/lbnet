#include "stdafx.h"
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#define DLL_API EXTERN_C __declspec(dllexport) 
#define cbMaxMessage 12000
#define IO_BUFFER_SIZE  0x10000

#define TLS_Wrapper_Version 8

extern WSADATA wsaData;
extern ULONG lastError;

#ifdef _DEBUG
extern HANDLE debugFile;

void WriteDebugLog(LPCSTR message);
#endif

DLL_API BOOL __stdcall IsReadAvailable(SOCKET sock, int msTimeout);


typedef struct TLSCtxtWrapper
{
	DWORD WrapperVersion;
	SOCKET sock;
	PCredHandle pCredHandle;
	PCtxtHandle pCtxtHandle;
	SecPkgContext_StreamSizes sizes;
	SecBuffer ExtraData;
	SecBuffer RemainingDecryptData;
	PCCERT_CONTEXT pCertContext;
	BOOL isServerContext;
} *PTLSCtxtWrapper;

