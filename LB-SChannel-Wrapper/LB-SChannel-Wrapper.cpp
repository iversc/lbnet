// LB-SChannel-Wrapper.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>
#include <WinSock2.h>
#include <WS2tcpip.h>

#define DLL_API EXTERN_C __declspec(dllexport) 

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ws2_32.lib")

#define cbMaxMessage 12000
#define IO_BUFFER_SIZE  0x10000

#define TLS_Wrapper_Version 7

WSADATA wsaData;
ULONG lastError = 0;

typedef struct TLSCtxtWrapper
{
	DWORD WrapperVersion;
	SOCKET sock;
	PCredHandle pCredHandle;
	PCtxtHandle pCtxtHandle;
	SecPkgContext_StreamSizes sizes;
	SecBuffer ExtraData;
	SecBuffer RemainingDecryptData;
} * PTLSCtxtWrapper;

#ifdef _DEBUG
HANDLE debugFile = INVALID_HANDLE_VALUE;
#endif

SECURITY_STATUS WrapperCheck(PTLSCtxtWrapper pWrapper)
{
	if (!pWrapper) return SEC_E_INVALID_HANDLE;
	if (pWrapper->WrapperVersion != TLS_Wrapper_Version) return SEC_E_INVALID_HANDLE;

	return SEC_E_OK;
}

#ifdef _DEBUG
void WriteDebugLog(LPCSTR message)
{
	if (debugFile != INVALID_HANDLE_VALUE)
	{
		DWORD msgLen = strlen(message);
		DWORD written = 0;
		WriteFile(debugFile, message, msgLen, &written, NULL);
	}
}
#endif

DLL_API ULONG __stdcall GetError()
{
	return lastError;
}

DLL_API SOCKET __stdcall Connect(LPCSTR pHost, LPCSTR pService, ULONG msTimeout)
{
	TIMEVAL tv = TIMEVAL();
	//Make sure we were actually passed strings to use.
	//getaddrinfo() will do further checking, and we will return INVALID_SOCKET then,
	//if necessary.
	if (pHost == NULL || pService == NULL)
	{
		lastError = ERROR_INVALID_PARAMETER;
		return INVALID_SOCKET;
	}

	//Initialize Winsock.
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		//Winsock init failed.
		lastError = iResult;
		return INVALID_SOCKET;
	}

	//Hints are used to tell getaddrinfo() what kind of socket we're intending to use
	//You can specify family(IPv4, IPv6, UNIX, Unspecified/any, etc),
	//socket type(stream or datagram, basically connection-oriented(TCP) or connectionless(UDP)),
	//and protocol(TCP, UDP, RAW, etc).
    //
	//The options we use here are going to be TCP/stream, with unspecified socket family, so
	//we can connect to either IPv4 or IPv6 servers without changing code.
	addrinfo hints = addrinfo();
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	addrinfo * result = NULL;
	addrinfo * ptr = NULL;

	DWORD dwResult = getaddrinfo(pHost, pService, &hints, &result);
	if (dwResult != 0)
	{
		//getaddrinfo() failed.
		lastError = dwResult;
		return INVALID_SOCKET;
	}

	if (msTimeout > 0)
	{
		tv.tv_sec = msTimeout / 1000;
		tv.tv_usec = msTimeout % 1000;
	}

	//Successful call to getaddrinfo().
	//Next, we go down the linked list of possible connections that
	//getaddrinfo() returned, and try to connect to each one until we succeed.

	SOCKET s = INVALID_SOCKET;

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		if (s == INVALID_SOCKET)
		{
			//This will only happen after the initial socket open if 
			//a timeout causes a socket to be prematurely closed.
			s = socket(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP);
			if (s == INVALID_SOCKET)
			{
				freeaddrinfo(result);
				return INVALID_SOCKET;
			}
		}

		//Handle the timeout if the user asked for one
		if (msTimeout > 0)
		{
			//Set socket to nonblocking
			ULONG block = TRUE;
			if (ioctlsocket(s, FIONBIO, &block) == SOCKET_ERROR)
			{
				lastError = WSAGetLastError();
				freeaddrinfo(result);
				closesocket(s);
				return INVALID_SOCKET;
			}
		}

		if (connect(s, ptr->ai_addr, ptr->ai_addrlen) != SOCKET_ERROR)
		{
			freeaddrinfo(result);
			return s;
		}
		else
		{
			//Only perform further manipulation if timeout is requested
			//Socket is currently nonblocking, so any call will return instantly
			if (msTimeout > 0)
			{
				//Only do further processing if the connect() call is in 
				//non-blocking progress.  Other errors will proceed as normal.
				if (WSAGetLastError() == WSAEWOULDBLOCK)
				{
					fd_set connSet;
					FD_ZERO(&connSet);
					FD_SET(s, &connSet);

					if (select(0, NULL, &connSet, NULL, &tv) == SOCKET_ERROR)
					{
						lastError = WSAGetLastError();
						freeaddrinfo(result);
						closesocket(s);
						return INVALID_SOCKET;
					}

					//If the socket is still in the fd_set after the call to select(),
					//it's become writable(i.e. connection has succeeded.)
					//
					//If not, we close the socket on our end(as the connection attempt is still
					//happening in the background), and create a new socket for further attempts.
					if (FD_ISSET(s, &connSet))
					{
						freeaddrinfo(result);

						//Successfully connected.  Set the socket back to blocking mode.
						ULONG block = FALSE;
						if (ioctlsocket(s, FIONBIO, &block) == SOCKET_ERROR)
						{
							lastError = WSAGetLastError();
							closesocket(s);
							return INVALID_SOCKET;
						}
						return s;
					}
					else
					{
						closesocket(s);
						s = INVALID_SOCKET;
					}
				}
			}
		}
	}

	lastError = WSAETIMEDOUT;
	//Free memory returned from getaddrinfo() once we don't need it anymore.
	freeaddrinfo(result);
	closesocket(s);
	return INVALID_SOCKET;
}

DLL_API int __stdcall Send(SOCKET s, LPCSTR buffer, ULONG bufLen)
{
	int retVal = send(s, buffer, bufLen, 0);
	if (retVal == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
	}

	return retVal;
}

DLL_API int __stdcall Receive(SOCKET s, LPSTR buffer, ULONG bufLen)
{
	int retVal = recv(s, buffer, bufLen, 0);
	if (retVal == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
	}

	return retVal;
}

DLL_API BOOL __stdcall IsSocketInvalid(SOCKET sock)
{
	return sock == INVALID_SOCKET;
}

DLL_API ULONG __stdcall CloseSocket(SOCKET sock)
{
	int retVal = closesocket(sock);
	WSACleanup();

	return retVal;
}

DLL_API PTLSCtxtWrapper __stdcall InitTLS()
{
	PTLSCtxtWrapper pWrapper = new TLSCtxtWrapper();
	pWrapper->WrapperVersion = TLS_Wrapper_Version;

#ifdef _DEBUG
	debugFile = CreateFile("wrapperdebug.log", GENERIC_ALL, FILE_SHARE_READ, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#endif

	return pWrapper;
}

DLL_API SECURITY_STATUS __stdcall EndTLS(PTLSCtxtWrapper pWrapper)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	if (pWrapper->pCtxtHandle != NULL) {
		DeleteSecurityContext(pWrapper->pCtxtHandle);
		delete pWrapper->pCtxtHandle;
	}

	if (pWrapper->pCredHandle != NULL) {
		FreeCredentialHandle(pWrapper->pCredHandle);
		delete pWrapper->pCredHandle;
	}

	if (pWrapper->ExtraData.BufferType != SECBUFFER_EMPTY)
	{
		HeapFree(GetProcessHeap(),0,pWrapper->ExtraData.pvBuffer);
	}

	if (pWrapper->RemainingDecryptData.BufferType != SECBUFFER_EMPTY)
	{
		HeapFree(GetProcessHeap(), 0, pWrapper->RemainingDecryptData.pvBuffer);
	}

	delete pWrapper;

#ifdef _DEBUG
	if (debugFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(debugFile);
		debugFile = INVALID_HANDLE_VALUE;
	}
#endif

	return SEC_E_OK;
}

DLL_API SECURITY_STATUS __stdcall SetTLSSocket(PTLSCtxtWrapper pWrapper, SOCKET sock)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	pWrapper->sock = sock;

	return SEC_E_OK;
}

SECURITY_STATUS BeginTLSClientInternal(PTLSCtxtWrapper pWrapper, DWORD dwFlags)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	pWrapper->pCredHandle = new CredHandle();
	SCHANNEL_CRED sc = SCHANNEL_CRED();
	sc.dwVersion = SCHANNEL_CRED_VERSION;
	sc.dwFlags = dwFlags;

	return AcquireCredentialsHandle(NULL, const_cast<LPSTR>(UNISP_NAME), SECPKG_CRED_OUTBOUND, NULL,
		&sc, NULL, NULL, pWrapper->pCredHandle, NULL);
}

DLL_API SECURITY_STATUS __stdcall BeginTLSClientNoValidation(PTLSCtxtWrapper pWrapper)
{
	DWORD dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;
	return BeginTLSClientInternal(pWrapper, dwFlags);
} 

DLL_API SECURITY_STATUS __stdcall BeginTLSClient(PTLSCtxtWrapper pWrapper)
{
	return BeginTLSClientInternal(pWrapper, 0);
}

SECURITY_STATUS RunHandshakeLoop(PTLSCtxtWrapper pWrapper, BOOL read)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	SecBufferDesc InputBufDesc, OutputBufDesc;
	SecBuffer InputBuf[2], OutputBuf[1];
	LPSTR inpBuf = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IO_BUFFER_SIZE);
	int bufCount = 0;
	int bufSize = IO_BUFFER_SIZE;
	DWORD dwFlagsRet = 0;

	if (inpBuf == NULL)
	{
		return SEC_E_INTERNAL_ERROR;
	}

	SECURITY_STATUS scRet = SEC_I_CONTINUE_NEEDED;

#ifdef _DEBUG
	WriteDebugLog("Entered RunHandshakeLoop\r\n");
#endif

	while (scRet == SEC_I_CONTINUE_NEEDED ||
		scRet == SEC_E_INCOMPLETE_MESSAGE)
	{
		if (bufCount == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			if (read)
			{
				ULONG size = recv(pWrapper->sock, inpBuf + bufCount, IO_BUFFER_SIZE - bufCount, 0);

				if (size == SOCKET_ERROR)
				{
					lastError = WSAGetLastError();
					scRet = SEC_E_INTERNAL_ERROR;
					break;
				}
				if (size == 0)
				{
					lastError = WSAEDISCON;
					scRet = SEC_E_INTERNAL_ERROR;
					break;
				}

				bufCount += size;
			}
			else {
				read = TRUE;
			}
		}

#ifdef _DEBUG
		WriteDebugLog("Received handshake data - processing message\r\n");
#endif

		InputBufDesc.cBuffers = 2;
		InputBufDesc.pBuffers = InputBuf;
		InputBufDesc.ulVersion = SECBUFFER_VERSION;

		InputBuf[0].BufferType = SECBUFFER_TOKEN;
		InputBuf[0].pvBuffer = inpBuf;
		InputBuf[0].cbBuffer = bufCount;

		InputBuf[1].BufferType = SECBUFFER_EMPTY;
		InputBuf[1].pvBuffer = NULL;
		InputBuf[1].cbBuffer = 0;

		OutputBufDesc.cBuffers = 1;
		OutputBufDesc.pBuffers = OutputBuf;
		OutputBufDesc.ulVersion = SECBUFFER_VERSION;

		OutputBuf[0].BufferType = SECBUFFER_TOKEN;
		OutputBuf[0].cbBuffer = 0;
		OutputBuf[0].pvBuffer = NULL;

		scRet = InitializeSecurityContext(pWrapper->pCredHandle, pWrapper->pCtxtHandle, NULL, ISC_REQ_CONFIDENTIALITY |
			ISC_REQ_ALLOCATE_MEMORY, 0, 0, &InputBufDesc, 0, NULL, &OutputBufDesc, &dwFlagsRet, NULL);

#ifdef _DEBUG
		WriteDebugLog("InitializeSecurityContext() called.\r\n");
		if (scRet == SEC_E_INTERNAL_ERROR)
		{
			WriteDebugLog("    Internal error returned\r\n");
		}
#endif

		if (scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED ||
			FAILED(scRet) && (dwFlagsRet & ISC_REQ_EXTENDED_ERROR))
		{
			if (OutputBuf[0].cbBuffer != 0 && OutputBuf[0].pvBuffer != NULL)
			{
				int sent = send(pWrapper->sock, (LPCSTR)OutputBuf[0].pvBuffer, OutputBuf[0].cbBuffer, 0);
				if(sent == SOCKET_ERROR)
				{
					lastError = WSAGetLastError();
					HeapFree(GetProcessHeap(), 0, inpBuf);
					return SEC_E_INTERNAL_ERROR;
				}
			}
		}

		if (scRet == SEC_E_INCOMPLETE_MESSAGE) continue;

		if (scRet == SEC_E_OK)
		{
			if (InputBuf[1].BufferType == SECBUFFER_EXTRA)
			{
				if (pWrapper->ExtraData.BufferType == SECBUFFER_EMPTY)
				{
					pWrapper->ExtraData.pvBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
						InputBuf[1].cbBuffer);

					if (pWrapper->ExtraData.pvBuffer == NULL)
					{
						return SEC_E_INTERNAL_ERROR;
					}

					MoveMemory(pWrapper->ExtraData.pvBuffer, InputBuf[1].pvBuffer,
						InputBuf[1].cbBuffer);

					pWrapper->ExtraData.cbBuffer = InputBuf[1].cbBuffer;
					pWrapper->ExtraData.BufferType = SECBUFFER_TOKEN;
				}
				else
				{
					PVOID newBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, InputBuf[1].cbBuffer + pWrapper->ExtraData.cbBuffer);
					if (newBuf == NULL)
					{
						return SEC_E_INTERNAL_ERROR;
					}

					CopyMemory(newBuf, pWrapper->ExtraData.pvBuffer, pWrapper->ExtraData.cbBuffer);
					CopyMemory((char*)newBuf + pWrapper->ExtraData.cbBuffer, InputBuf[1].pvBuffer, InputBuf[1].cbBuffer);
					HeapFree(GetProcessHeap(),0,pWrapper->ExtraData.pvBuffer);
					pWrapper->ExtraData.pvBuffer = newBuf;

					pWrapper->ExtraData.cbBuffer += InputBuf[1].cbBuffer;
				}
			}

			break;
		}

		if (FAILED(scRet))
		{
			return scRet;
		}

		if (InputBuf[1].BufferType == SECBUFFER_EXTRA)
		{
			MoveMemory(inpBuf, InputBuf[1].pvBuffer, InputBuf[1].cbBuffer);
			bufCount = InputBuf[1].cbBuffer;
		}
		else
		{
			bufCount = 0;
		}
	} //while scRet ==

	HeapFree(GetProcessHeap(),0,inpBuf);
	return scRet;
}

DLL_API SECURITY_STATUS __stdcall PerformClientHandshake(PTLSCtxtWrapper pWrapper, LPSTR pServerName)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	SecBufferDesc OutputBufDesc;
	SecBuffer OutputBuf;

	OutputBufDesc.ulVersion = SECBUFFER_VERSION;
	OutputBufDesc.cBuffers = 1;
	OutputBufDesc.pBuffers = &OutputBuf;

	OutputBuf.BufferType = SECBUFFER_TOKEN;
	OutputBuf.cbBuffer = 0;
	OutputBuf.pvBuffer = NULL;

	pWrapper->pCtxtHandle = new CtxtHandle();
	DWORD dwSSPIOutFlags = 0;

	SECURITY_STATUS scRet = InitializeSecurityContext(pWrapper->pCredHandle, NULL, pServerName,
		ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY, 0, 0, NULL, 0, pWrapper->pCtxtHandle, &OutputBufDesc,
		&dwSSPIOutFlags, NULL);

	if (scRet != SEC_I_CONTINUE_NEEDED) {
		return scRet;
	}

	if (OutputBuf.cbBuffer != 0 && OutputBuf.pvBuffer != NULL)
	{
		int sent = send(pWrapper->sock, (LPCSTR)OutputBuf.pvBuffer, OutputBuf.cbBuffer, 0);
		if (sent == SOCKET_ERROR)
		{
			lastError = WSAGetLastError();
			FreeContextBuffer(OutputBuf.pvBuffer);
			return SEC_E_INTERNAL_ERROR;
		}

		FreeContextBuffer(OutputBuf.pvBuffer);
	}

	scRet = RunHandshakeLoop(pWrapper, TRUE);

	if (scRet != SEC_E_OK)
	{
		return scRet;
	}

	SECURITY_STATUS qcaRet = QueryContextAttributes(pWrapper->pCtxtHandle, SECPKG_ATTR_STREAM_SIZES, &pWrapper->sizes);
	if (qcaRet != SEC_E_OK)
	{
		return qcaRet;
	}

	return scRet;
}

DLL_API int __stdcall EncryptSend(PTLSCtxtWrapper pWrapper, LPCSTR message, ULONG msgLen)
{
	if (FAILED(WrapperCheck(pWrapper))) {
		lastError = SEC_E_INVALID_HANDLE;
		return SOCKET_ERROR;
	}
	if (!message) {
		lastError = SEC_E_ILLEGAL_MESSAGE;
		return SOCKET_ERROR;
	}

	PSecPkgContext_StreamSizes sizes = &pWrapper->sizes;
	int messageSize = msgLen;

	int maxMessageBlobSize = sizes->cbHeader + sizes->cbMaximumMessage +
		sizes->cbTrailer;

	PBYTE sendBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, maxMessageBlobSize);
	if (sendBuf == NULL)
	{
		lastError = SEC_E_INSUFFICIENT_MEMORY;
		return SOCKET_ERROR;
	}

	MoveMemory(sendBuf + sizes->cbHeader, message, messageSize);

	SecBufferDesc MessageDesc;
	SecBuffer MsgBuffer[4];

	MsgBuffer[0].BufferType = SECBUFFER_STREAM_HEADER;
	MsgBuffer[0].cbBuffer = sizes->cbHeader;
	MsgBuffer[0].pvBuffer = sendBuf;

	MsgBuffer[1].BufferType = SECBUFFER_DATA;
	MsgBuffer[1].pvBuffer = sendBuf + sizes->cbHeader;
	MsgBuffer[1].cbBuffer = messageSize;

	MsgBuffer[2].BufferType = SECBUFFER_STREAM_TRAILER;
	MsgBuffer[2].cbBuffer = sizes->cbTrailer;
	MsgBuffer[2].pvBuffer = sendBuf + sizes->cbHeader + messageSize;

	MsgBuffer[3].BufferType = SECBUFFER_EMPTY;
	MsgBuffer[3].cbBuffer = 0;
	MsgBuffer[3].pvBuffer = NULL;

	MessageDesc.cBuffers = 4;
	MessageDesc.ulVersion = SECBUFFER_VERSION;
	MessageDesc.pBuffers = MsgBuffer;

	SECURITY_STATUS scRet = EncryptMessage(pWrapper->pCtxtHandle, 0, &MessageDesc, 0);
	if (FAILED(scRet))
	{
		HeapFree(GetProcessHeap(),0,sendBuf);
		lastError = scRet;
		return SOCKET_ERROR;
	}

	int sent = send(pWrapper->sock, (LPSTR)sendBuf, messageSize + sizes->cbHeader + sizes->cbTrailer, 0);
	if (sent == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
		HeapFree(GetProcessHeap(),0,sendBuf);
		return SOCKET_ERROR;
	}

	HeapFree(GetProcessHeap(),0,sendBuf);
	return sent;
}

DLL_API int __stdcall DecryptReceive(PTLSCtxtWrapper pWrapper, LPSTR buffer, ULONG bufLen)
{
	if (FAILED(WrapperCheck(pWrapper)))
	{
		lastError = SEC_E_INVALID_HANDLE;
		return SOCKET_ERROR;
	}
	if (!buffer)
	{
		lastError = SEC_E_ILLEGAL_MESSAGE;
		return SOCKET_ERROR;
	}

	SECURITY_STATUS scRet = 0;
	SecBufferDesc MessageBufDesc;
	SecBuffer MsgBuffer[4];
	PSecBuffer pDataBuf = NULL, pExtraBuf = NULL;
	int decryptBufSize = pWrapper->sizes.cbHeader + pWrapper->sizes.cbMaximumMessage
		+ pWrapper->sizes.cbTrailer;
	int decryptBufUsed = 0;
	PBYTE decryptBuf = NULL;
	int retAmount = 0;

	//See if there's anything left to return from our last DecryptReceive() call
	PSecBuffer pRemnant = &pWrapper->RemainingDecryptData;
	if (pRemnant->BufferType != SECBUFFER_EMPTY)
	{
		int min = min(bufLen, pRemnant->cbBuffer);
		CopyMemory(buffer, pRemnant->pvBuffer, min);
		if (pRemnant->cbBuffer > bufLen)
		{
			MoveMemory(pRemnant->pvBuffer, (char*)pRemnant->pvBuffer + bufLen, pRemnant->cbBuffer - bufLen);
			pRemnant->cbBuffer = pRemnant->cbBuffer - bufLen;
		}
		else
		{
			HeapFree(GetProcessHeap(),0,pRemnant->pvBuffer);
			pRemnant->pvBuffer = NULL;
			pRemnant->cbBuffer = 0;
			pRemnant->BufferType = SECBUFFER_EMPTY;
		}

		return min;
	}

	decryptBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decryptBufSize);
	if (decryptBuf == NULL)
	{
		lastError = SEC_E_INSUFFICIENT_MEMORY;
		return SOCKET_ERROR;
	}

	PSecBuffer pExtra = &pWrapper->ExtraData;
	if (pExtra->BufferType != SECBUFFER_EMPTY)
	{
		CopyMemory(decryptBuf, pExtra->pvBuffer, pExtra->cbBuffer);
		decryptBufUsed = pExtra->cbBuffer;

		pExtra->BufferType = SECBUFFER_EMPTY;
		pExtra->cbBuffer = 0;
		HeapFree(GetProcessHeap(),0,pExtra->pvBuffer);
		pExtra->pvBuffer = NULL;

		scRet = SEC_E_INCOMPLETE_MESSAGE;
	}

	while (TRUE)
	{
		if (decryptBufUsed == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			int received = recv(pWrapper->sock, (LPSTR)decryptBuf + decryptBufUsed, decryptBufSize - decryptBufUsed, 0);
			if (received == SOCKET_ERROR)
			{
				lastError = WSAGetLastError();
				HeapFree(GetProcessHeap(), 0, decryptBuf);
				return SOCKET_ERROR;
			}
			if (received == 0)
			{
				lastError = WSAEDISCON;
				HeapFree(GetProcessHeap(), 0, decryptBuf);
				return SOCKET_ERROR;
			}
			decryptBufUsed += received;
		}

		MessageBufDesc.ulVersion = SECBUFFER_VERSION;
		MessageBufDesc.cBuffers = 4;
		MessageBufDesc.pBuffers = MsgBuffer;

		MsgBuffer[0].BufferType = SECBUFFER_DATA;
		MsgBuffer[0].cbBuffer = decryptBufUsed;
		MsgBuffer[0].pvBuffer = decryptBuf;

		MsgBuffer[1] = SecBuffer();
		MsgBuffer[2] = SecBuffer();
		MsgBuffer[3] = SecBuffer();

		scRet = DecryptMessage(pWrapper->pCtxtHandle, &MessageBufDesc, 0, NULL);

		if (scRet == SEC_I_CONTEXT_EXPIRED) break;  //Server signalled end-of-session
		if (scRet != SEC_E_OK && scRet != SEC_I_RENEGOTIATE
			&& scRet != SEC_I_CONTEXT_EXPIRED)
		{
			lastError = scRet;
			HeapFree(GetProcessHeap(),0,decryptBuf);
			return SOCKET_ERROR;
		}

		for (int i = 0; i < 4; i++)
		{
			if (pDataBuf == NULL && MsgBuffer[i].BufferType == SECBUFFER_DATA) pDataBuf = &MsgBuffer[i];
			if (pExtraBuf == NULL && MsgBuffer[i].BufferType == SECBUFFER_EXTRA) pExtraBuf = &MsgBuffer[i];
		}

		if (pExtraBuf)
		{
			pExtra->BufferType = SECBUFFER_EXTRA;
			pExtra->cbBuffer = pExtraBuf->cbBuffer;
			pExtra->pvBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pExtra->cbBuffer);

			CopyMemory(pExtra->pvBuffer, pExtraBuf->pvBuffer, pExtra->cbBuffer);
		}

		if (pDataBuf)
		{
			ULONG length = pDataBuf->cbBuffer;
			retAmount = min(length, bufLen);
			CopyMemory(buffer, pDataBuf->pvBuffer, min(length, bufLen));

			if (length > bufLen)
			{
				int diff = length - bufLen;
				pRemnant->BufferType = SECBUFFER_DATA;
				pRemnant->cbBuffer = diff;
				pRemnant->pvBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, diff);
				if (pRemnant->pvBuffer == NULL)
				{
					lastError = SEC_E_INSUFFICIENT_MEMORY;
					HeapFree(GetProcessHeap(),0,decryptBuf);
					return SOCKET_ERROR;
				}

				CopyMemory(pRemnant->pvBuffer, (char*)pDataBuf->pvBuffer + bufLen, diff);
			}

			break;
		}

		if (scRet == SEC_I_RENEGOTIATE)
		{
			scRet = RunHandshakeLoop(pWrapper, FALSE);
			if (scRet != SEC_E_OK)
			{
				HeapFree(GetProcessHeap(),0,decryptBuf);
				return scRet;
			}
		}

	} // while (TRUE)

	return retAmount;
}