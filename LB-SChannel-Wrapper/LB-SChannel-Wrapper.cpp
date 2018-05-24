// LB-SChannel-Wrapper.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "mesock32.h"
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>

#define DLL_API EXTERN_C __declspec(dllexport) 

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "mesock32.lib")

#define cbMaxMessage 12000
#define IO_BUFFER_SIZE  0x10000

#define TLS_Wrapper_Version 6

typedef struct TLSCtxtWrapper
{
	DWORD WrapperVersion;
	Mesock32Socket sock;
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

DLL_API SECURITY_STATUS __stdcall SetTLSSocket(PTLSCtxtWrapper pWrapper, Mesock32Socket sock)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	pWrapper->sock = sock;

	return SEC_E_OK;
}

DLL_API SECURITY_STATUS __stdcall BeginTLSClientNoValidation(PTLSCtxtWrapper pWrapper)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	pWrapper->pCredHandle = new CredHandle();
	SCHANNEL_CRED sc = SCHANNEL_CRED();
	sc.dwVersion = SCHANNEL_CRED_VERSION;
	sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_NO_SERVERNAME_CHECK;

	return AcquireCredentialsHandle(NULL, const_cast<LPSTR>(UNISP_NAME), SECPKG_CRED_OUTBOUND, NULL,
		&sc, NULL, NULL, pWrapper->pCredHandle, NULL);
} 

SECURITY_STATUS RunHandshakeLoop(PTLSCtxtWrapper pWrapper, BOOL read)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	SecBufferDesc InputBufDesc, OutputBufDesc;
	SecBuffer InputBuf[2], OutputBuf;
	PVOID inpBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IO_BUFFER_SIZE);
	PVOID received = 0;
	int bufCount = 0;
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
				received = Receive(pWrapper->sock, IO_BUFFER_SIZE - bufCount, 0);
				ULONG size = strnlen_s(reinterpret_cast<const char*>(received), IO_BUFFER_SIZE - bufCount);

				if (size == 0)
				{
					return SEC_E_INTERNAL_ERROR;
				}

				int dest = reinterpret_cast<int>(inpBuf) + bufCount;
				MoveMemory(inpBuf, received, size);
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

		OutputBufDesc.cBuffers = 1;
		OutputBufDesc.pBuffers = NULL;
		OutputBufDesc.ulVersion = SECBUFFER_VERSION;

		OutputBuf.BufferType = SECBUFFER_EMPTY;
		OutputBuf.cbBuffer = 0;
		OutputBuf.pvBuffer = NULL;

		scRet = InitializeSecurityContext(pWrapper->pCredHandle, pWrapper->pCtxtHandle, NULL, ISC_REQ_CONFIDENTIALITY |
			ISC_REQ_ALLOCATE_MEMORY, 0, 0, &InputBufDesc, 0, NULL, &OutputBufDesc, &dwFlagsRet, NULL);

#ifdef _DEBUG
		WriteDebugLog("InitializeSecurityContext() called.\r\n");
		if (scRet == SEC_E_INVALID_HANDLE)
		{
			WriteDebugLog("    Invalid Handle returned\r\n");
		}
#endif

		if (scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED ||
			FAILED(scRet) && (dwFlagsRet & ISC_REQ_EXTENDED_ERROR))
		{
			if (OutputBuf.cbBuffer != 0 && OutputBuf.pvBuffer != NULL)
			{
				if (!Send(pWrapper->sock, OutputBuf.pvBuffer))
				{
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
		}

		break;

		if (FAILED(scRet))
		{
			return scRet;
		}

		if (InputBuf[1].BufferType == SECBUFFER_EXTRA)
		{
			MoveMemory(inpBuf, InputBuf[1].pvBuffer, InputBuf[1].cbBuffer);
			bufCount = InputBuf[1].cbBuffer;
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
		if (!Send(pWrapper->sock, OutputBuf.pvBuffer))
		{
			return SEC_E_INTERNAL_ERROR;
		}

		FreeContextBuffer(OutputBuf.pvBuffer);
	}

	scRet = RunHandshakeLoop(pWrapper, TRUE);

	SECURITY_STATUS qcaRet = QueryContextAttributes(pWrapper->pCtxtHandle, SECPKG_ATTR_STREAM_SIZES, &pWrapper->sizes);
	if (qcaRet != SEC_E_OK)
	{
		return qcaRet;
	}

	return scRet;
}

DLL_API SECURITY_STATUS __stdcall EncryptSend(PTLSCtxtWrapper pWrapper, LPCSTR message)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;
	if (!message) return SEC_E_ILLEGAL_MESSAGE;

	PSecPkgContext_StreamSizes sizes = &pWrapper->sizes;
	int messageSize = strnlen_s(message, sizes->cbMaximumMessage);

	int maxMessageBlobSize = sizes->cbHeader + sizes->cbMaximumMessage +
		sizes->cbTrailer;

	PBYTE sendBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, maxMessageBlobSize);
	if (sendBuf == NULL)
	{
		return SEC_E_INTERNAL_ERROR;
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

	SECURITY_STATUS scRet = EncryptMessage(pWrapper->pCtxtHandle, 0, &MessageDesc, 0);
	if (FAILED(scRet))
	{
		HeapFree(GetProcessHeap(),0,sendBuf);
		return scRet;
	}

	if (!Send(pWrapper->sock, sendBuf))
	{
		HeapFree(GetProcessHeap(),0,sendBuf);
		return SEC_E_INTERNAL_ERROR;
	}

	HeapFree(GetProcessHeap(),0,sendBuf);
	return scRet;
}

DLL_API SECURITY_STATUS __stdcall DecryptReceive(PTLSCtxtWrapper pWrapper, LPSTR buffer, ULONG bufLen)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;
	if (!buffer) return SEC_E_ILLEGAL_MESSAGE;

	SECURITY_STATUS scRet = 0;
	SecBufferDesc MessageBufDesc;
	SecBuffer MsgBuffer[4];
	PSecBuffer pDataBuf = NULL, pExtraBuf = NULL;
	int decryptBufSize = pWrapper->sizes.cbHeader + pWrapper->sizes.cbMaximumMessage
		+ pWrapper->sizes.cbTrailer;
	int decryptBufUsed = 0;
	PBYTE decryptBuf = NULL, receiveBuf;

	//See if there's anything left to return from our last DecryptReceive() call
	PSecBuffer pRemnant = &pWrapper->RemainingDecryptData;
	if (pRemnant->BufferType != SECBUFFER_EMPTY)
	{
		CopyMemory(buffer, pRemnant->pvBuffer, min(bufLen, pRemnant->cbBuffer));
		if (pRemnant->cbBuffer > bufLen)
		{
			MoveMemory(pRemnant->pvBuffer, (char*)pRemnant->pvBuffer + bufLen, pRemnant->cbBuffer - bufLen);
			pRemnant->cbBuffer = pRemnant->cbBuffer - bufLen;
			return SEC_E_OK;
		}
		else
		{
			HeapFree(GetProcessHeap(),0,pRemnant->pvBuffer);
			pRemnant->pvBuffer = NULL;
			pRemnant->cbBuffer = 0;
			pRemnant->BufferType = SECBUFFER_EMPTY;
		}
	}

	decryptBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, decryptBufSize);
	if (decryptBuf == NULL)
	{
		return SEC_E_INTERNAL_ERROR;
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
			receiveBuf = (PBYTE)Receive(pWrapper->sock, decryptBufSize - decryptBufUsed, 0);
			ULONG recvBufSize = strnlen_s((const char *)receiveBuf, decryptBufSize - decryptBufUsed);
			if (recvBufSize == 0)
			{
				HeapFree(GetProcessHeap(),0,decryptBuf);
				return SEC_E_INTERNAL_ERROR;
			}

			CopyMemory(decryptBuf + decryptBufUsed, receiveBuf, recvBufSize);
			decryptBufUsed += recvBufSize;
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
			HeapFree(GetProcessHeap(),0,decryptBuf);
			return scRet;
		}

		for (int i = 0; i < 4; i++)
		{
			if (pDataBuf == NULL && MsgBuffer[i].BufferType == SECBUFFER_DATA) pDataBuf = &MsgBuffer[i];
			if (pExtraBuf == NULL && MsgBuffer[i].BufferType == SECBUFFER_EXTRA) pExtraBuf = &MsgBuffer[i];
		}

		if (pDataBuf)
		{
			ULONG length = pDataBuf->cbBuffer;
			CopyMemory(buffer, pDataBuf->pvBuffer, min(length, bufLen));

			if (length > bufLen)
			{
				int diff = length - bufLen;
				pRemnant->BufferType = SECBUFFER_DATA;
				pRemnant->cbBuffer = diff;
				pRemnant->pvBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, diff);
				if (pRemnant->pvBuffer == NULL)
				{
					HeapFree(GetProcessHeap(),0,decryptBuf);
					return SEC_E_INTERNAL_ERROR;
				}

				CopyMemory(pRemnant->pvBuffer, (char*)pDataBuf->pvBuffer + bufLen, diff);
				break;
			}
		}

		if (pExtraBuf)
		{
			pExtra->BufferType = SECBUFFER_EXTRA;
			pExtra->cbBuffer = pExtraBuf->cbBuffer;
			pExtra->pvBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pExtra->cbBuffer);

			CopyMemory(pExtra->pvBuffer, pExtraBuf->pvBuffer, pExtra->cbBuffer);
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

	return SEC_E_OK;
}