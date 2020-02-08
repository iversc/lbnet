#include "stdafx.h"
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#define LBNET_API EXTERN_C __declspec(dllexport)
#define IO_BUFFER_SIZE  0x10000

#define LBNet_Version 10

extern WSADATA wsaData;
extern ULONG lastError;

#ifdef _DEBUG
extern HANDLE debugFile;

void WriteDebugLog(LPCSTR function, LPCSTR message);
#endif

LBNET_API BOOL __stdcall IsReadAvailable(SOCKET sock, int msTimeout);


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
	BOOL acceptSuccess;
} *PTLSCtxtWrapper;

