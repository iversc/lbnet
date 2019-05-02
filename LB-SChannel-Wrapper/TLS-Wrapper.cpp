#include "stdafx.h"
#include "LB-SChannel-Wrapper.h"

SECURITY_STATUS WrapperCheck(PTLSCtxtWrapper pWrapper)
{
	if (!pWrapper) return SEC_E_INVALID_HANDLE;
	if (pWrapper->WrapperVersion != TLS_Wrapper_Version) return SEC_E_INVALID_HANDLE;

	return SEC_E_OK;
}

DLL_API PTLSCtxtWrapper __stdcall CreateTLSContext()
{
	PTLSCtxtWrapper pWrapper = new TLSCtxtWrapper();
	pWrapper->WrapperVersion = TLS_Wrapper_Version;

	return pWrapper;
}


DLL_API SECURITY_STATUS __stdcall DestroyTLSContext(PTLSCtxtWrapper pWrapper)
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
		HeapFree(GetProcessHeap(), 0, pWrapper->ExtraData.pvBuffer);
	}

	if (pWrapper->RemainingDecryptData.BufferType != SECBUFFER_EMPTY)
	{
		HeapFree(GetProcessHeap(), 0, pWrapper->RemainingDecryptData.pvBuffer);
	}

	if (pWrapper->pCertContext != NULL)
	{
		CertFreeCertificateContext(pWrapper->pCertContext);
	}

	delete pWrapper;

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

	pWrapper->isServerContext = false;

	return AcquireCredentialsHandle(NULL, const_cast<LPSTR>(UNISP_NAME), SECPKG_CRED_OUTBOUND, NULL,
		&sc, NULL, NULL, pWrapper->pCredHandle, NULL);
}

PCCERT_CONTEXT getServerCertificate()
{
	HCERTSTORE hStore = NULL;
	PCCERT_CONTEXT pCertContext = NULL;

	hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, NULL,
		CERT_SYSTEM_STORE_LOCAL_MACHINE, L"MY");

	if (hStore == NULL)
	{
		lastError = SEC_E_INCOMPLETE_CREDENTIALS;
		return NULL;
	}

	pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING,
		0, CERT_FIND_SUBJECT_STR_A, "localhost", NULL);

	CertCloseStore(hStore, 0);
	return pCertContext;
}

DLL_API SECURITY_STATUS BeginTLSServer(PTLSCtxtWrapper pWrapper)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	pWrapper->pCredHandle = new CredHandle();
	SCHANNEL_CRED sc = SCHANNEL_CRED();
	sc.dwVersion = SCHANNEL_CRED_VERSION;

	PCCERT_CONTEXT serverCert;

	sc.cSupportedAlgs = 0;
	sc.palgSupportedAlgs = NULL;

	sc.grbitEnabledProtocols = 0;
	sc.dwMaximumCipherStrength = 0;
	sc.dwMinimumCipherStrength = 0;
	sc.dwSessionLifespan = 0;


	serverCert = getServerCertificate();

	if (serverCert == NULL)
	{
		return SEC_E_INTERNAL_ERROR;
	}

	sc.paCred = &serverCert;

	pWrapper->pCertContext = serverCert;

	pWrapper->isServerContext = true;

	return AcquireCredentialsHandle(NULL, const_cast<LPSTR>(UNISP_NAME), SECPKG_CRED_INBOUND, NULL,
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

DLL_API SECURITY_STATUS __stdcall EndTLSClientSession(PTLSCtxtWrapper pWrapper)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	SecBufferDesc OutputBufDesc;
	SecBuffer OutputBuf[1];
	DWORD dwType, dwSSPIFlags, dwFlagsRet;
	TimeStamp expiration;

	SECURITY_STATUS scRet;

	dwType = SCHANNEL_SHUTDOWN;

	OutputBuf[0].pvBuffer = &dwType;
	OutputBuf[0].BufferType = SECBUFFER_TOKEN;
	OutputBuf[0].cbBuffer = sizeof(dwType);

	OutputBufDesc.cBuffers = 1;
	OutputBufDesc.pBuffers = OutputBuf;
	OutputBufDesc.ulVersion = SECBUFFER_VERSION;

	scRet = ApplyControlToken(pWrapper->pCtxtHandle, &OutputBufDesc);
	if (FAILED(scRet))
	{
		goto DFScleanup;
	}

	dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

	scRet = InitializeSecurityContext(pWrapper->pCredHandle, pWrapper->pCtxtHandle, NULL,
		dwSSPIFlags, 0, SECURITY_NATIVE_DREP, NULL, 0, pWrapper->pCtxtHandle, &OutputBufDesc,
		&dwFlagsRet, &expiration);

	if (FAILED(scRet))
	{
		goto DFScleanup;
	}

	if (OutputBuf[0].pvBuffer != NULL && OutputBuf[0].cbBuffer != 0)
	{
		int numSent = send(pWrapper->sock, (LPCSTR)OutputBuf[0].pvBuffer, OutputBuf[0].cbBuffer, 0);
		if (numSent == SOCKET_ERROR || numSent == 0)
		{
			scRet = WSAGetLastError();
			goto DFScleanup;
		}

		FreeContextBuffer(OutputBuf[0].pvBuffer);
	}

DFScleanup:
	DeleteSecurityContext(pWrapper->pCtxtHandle);
	delete pWrapper->pCtxtHandle;
	return scRet;
}

SECURITY_STATUS RunHandshakeLoop(PTLSCtxtWrapper pWrapper, BOOL read)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	SecBufferDesc InputBufDesc, OutputBufDesc;
	SecBuffer InputBuf[2], OutputBuf[2];
	LPSTR inpBuf = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, IO_BUFFER_SIZE);
	DWORD bufCount = 0;
	DWORD bufSize = IO_BUFFER_SIZE;
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

		OutputBufDesc.cBuffers = 2;
		OutputBufDesc.pBuffers = OutputBuf;
		OutputBufDesc.ulVersion = SECBUFFER_VERSION;

		OutputBuf[0].BufferType = SECBUFFER_TOKEN;
		OutputBuf[0].cbBuffer = 0;
		OutputBuf[0].pvBuffer = NULL;

		OutputBuf[1].BufferType = SECBUFFER_ALERT;
		OutputBuf[1].cbBuffer = 0;
		OutputBuf[1].pvBuffer = NULL;

		if (pWrapper->isServerContext)
		{
			scRet = AcceptSecurityContext(pWrapper->pCredHandle, pWrapper->pCtxtHandle, &InputBufDesc,
				ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM |
				ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_EXTENDED_ERROR,
				0, NULL, &OutputBufDesc, &dwFlagsRet, NULL);
		}
		else
		{
			scRet = InitializeSecurityContext(pWrapper->pCredHandle, pWrapper->pCtxtHandle, NULL,
				ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |
				ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_EXTENDED_ERROR,
				0, 0, &InputBufDesc, 0, NULL, &OutputBufDesc, &dwFlagsRet, NULL);
		}

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
				FreeContextBuffer(OutputBuf[0].pvBuffer);
				if (OutputBuf[1].pvBuffer != NULL)
				{
					FreeContextBuffer(OutputBuf[1].pvBuffer);
				}
				if (sent == SOCKET_ERROR)
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

#ifdef _DEBUG
					if (InputBuf[1].pvBuffer == NULL)
					{
						WriteDebugLog("InputBuf Extra NULL\r\n");
					}
					else
					{
						WriteDebugLog("InputBuf Extra NOTNULL\r\n");
					}
#endif
					MoveMemory(pWrapper->ExtraData.pvBuffer,
						inpBuf + (bufCount - InputBuf[1].cbBuffer),
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


#ifdef _DEBUG
					if (InputBuf[1].pvBuffer == NULL)
					{
						WriteDebugLog("InputBuf Extra NULL\r\n");
					}
					else
					{
						WriteDebugLog("InputBuf Extra NOTNULL\r\n");
					}
#endif

					CopyMemory(newBuf, pWrapper->ExtraData.pvBuffer, pWrapper->ExtraData.cbBuffer);
					CopyMemory((char*)newBuf + pWrapper->ExtraData.cbBuffer,
						inpBuf + (bufCount - InputBuf[1].cbBuffer), InputBuf[1].cbBuffer);
					HeapFree(GetProcessHeap(), 0, pWrapper->ExtraData.pvBuffer);
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

#ifdef _DEBUG
			if (InputBuf[1].pvBuffer == NULL)
			{
				WriteDebugLog("InputBuf Extra NULL\r\n");
			}
			else
			{
				WriteDebugLog("InputBuf Extra NOTNULL\r\n");
			}
#endif
			MoveMemory(inpBuf, inpBuf + (bufCount - InputBuf[1].cbBuffer), InputBuf[1].cbBuffer);
			bufCount = InputBuf[1].cbBuffer;
		}
		else
		{
			bufCount = 0;
		}
	} //while scRet ==

	HeapFree(GetProcessHeap(), 0, inpBuf);
	return scRet;
}

BOOL serverHandshakeDoInitialRead(SOCKET s, LPVOID * buffer, int * bufSize)
{
	int readSize = 1024;
	LPVOID readBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, readSize);

	if (readBuf == NULL)
	{
		lastError = SEC_E_INSUFFICIENT_MEMORY;
		return false;
	}

	int received = recv(s, (char *)readBuf, readSize, 0);
	if (received == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
		HeapFree(GetProcessHeap(), 0, readBuf);
		return false;
	}
	if (received == 0)
	{
		lastError = WSAEDISCON;
		HeapFree(GetProcessHeap(), 0, readBuf);
		return false;
	}

	*buffer = readBuf;
	*bufSize = received;
	return true;
}

DLL_API SECURITY_STATUS __stdcall PerformServerHandshake(PTLSCtxtWrapper pWrapper, BOOL bPerformInitialRead, LPSTR initBuf, ULONG initBufSize)
{
	if (FAILED(WrapperCheck(pWrapper))) return SEC_E_INVALID_HANDLE;

	SecBufferDesc OutputBufDesc, InputBufDesc;
	SecBuffer OutputBuf, InputBuf[2];
	LPVOID readBuf = NULL;

	OutputBufDesc.ulVersion = SECBUFFER_VERSION;
	OutputBufDesc.cBuffers = 1;
	OutputBufDesc.pBuffers = &OutputBuf;

	OutputBuf.BufferType = SECBUFFER_TOKEN;
	OutputBuf.cbBuffer = 0;
	OutputBuf.pvBuffer = NULL;

	pWrapper->pCtxtHandle = new CtxtHandle();
	DWORD dwSSPIOutFlags = 0;

	InputBufDesc.ulVersion = SECBUFFER_VERSION;
	InputBufDesc.cBuffers = 2;
	InputBufDesc.pBuffers = InputBuf;

	InputBuf[1].BufferType = SECBUFFER_EMPTY;
	InputBuf[1].cbBuffer = 0;
	InputBuf[1].pvBuffer = NULL;

	InputBuf[0].BufferType = SECBUFFER_TOKEN;

	if (bPerformInitialRead)
	{
		int received = 0;
		if (!serverHandshakeDoInitialRead(pWrapper->sock, &readBuf, &received))
		{
			return SOCKET_ERROR;
		}

		InputBuf[0].pvBuffer = readBuf;
		InputBuf[0].cbBuffer = received;
	}
	else
	{
		InputBuf[0].pvBuffer = initBuf;
		InputBuf[0].cbBuffer = initBufSize;
	}

	DWORD dwAASCFlags = ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM |
		ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_EXTENDED_ERROR;

	SECURITY_STATUS scRet = AcceptSecurityContext(pWrapper->pCredHandle, NULL, &InputBufDesc,
		dwAASCFlags, 0, pWrapper->pCtxtHandle, &OutputBufDesc, &dwSSPIOutFlags, NULL);

	if (readBuf != NULL)
	{
		HeapFree(GetProcessHeap(), 0, readBuf);
	}

	if (scRet != SEC_I_CONTINUE_NEEDED && scRet != SEC_E_INCOMPLETE_MESSAGE)
	{
		lastError = scRet;
		return scRet;
	}


	if (OutputBuf.cbBuffer != 0 && OutputBuf.pvBuffer != NULL && scRet != SEC_E_INCOMPLETE_MESSAGE)
	{
		int sent = send(pWrapper->sock, (LPCSTR)OutputBuf.pvBuffer, OutputBuf.cbBuffer, 0);
		FreeContextBuffer(OutputBuf.pvBuffer);

		if (sent == SOCKET_ERROR)
		{
			lastError = WSAGetLastError();		
			return SEC_E_INTERNAL_ERROR;
		}
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
		ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |
		ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_EXTENDED_ERROR,
		0, 0, NULL, 0, pWrapper->pCtxtHandle, &OutputBufDesc,
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
		HeapFree(GetProcessHeap(), 0, sendBuf);
		lastError = scRet;
		return SOCKET_ERROR;
	}

	int sent = send(pWrapper->sock, (LPSTR)sendBuf,
		MsgBuffer[0].cbBuffer + MsgBuffer[1].cbBuffer + MsgBuffer[2].cbBuffer, 0);
	if (sent == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
		HeapFree(GetProcessHeap(), 0, sendBuf);
		return SOCKET_ERROR;
	}

	HeapFree(GetProcessHeap(), 0, sendBuf);
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
			HeapFree(GetProcessHeap(), 0, pRemnant->pvBuffer);
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
		HeapFree(GetProcessHeap(), 0, pExtra->pvBuffer);
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
			HeapFree(GetProcessHeap(), 0, decryptBuf);
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
					HeapFree(GetProcessHeap(), 0, decryptBuf);
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
				HeapFree(GetProcessHeap(), 0, decryptBuf);
				return scRet;
			}
		}

	} // while (TRUE)

	return retAmount;
}

DLL_API BOOL __stdcall IsTLSReadAvailable(PTLSCtxtWrapper pWrapper, int msTimeout)
{
	if (FAILED(WrapperCheck(pWrapper)))
	{
		lastError = SEC_E_INVALID_HANDLE;
		return SOCKET_ERROR;
	}

	return IsReadAvailable(pWrapper->sock, msTimeout);
}