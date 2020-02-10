#include "stdafx.h"
#include "LBNet.h"

LBNET_API SOCKET __stdcall UDPConnect(LPCSTR pHost, LPCSTR pService, ULONG msTimeout)
{
	return ConnectInternal(pHost, pService, msTimeout, IPPROTO_UDP);
}

LBNET_API UINT __stdcall UDPGetInfoSize()
{
	return sizeof(LBNetUDPInfo);
}

LBNET_API int __stdcall UDPSend(SOCKET s, LPCSTR buffer, ULONG bufLen, PLBNetUDPInfo udpInfo)
{
	PSOCKADDR_STORAGE pSockAddr = NULL;
	int sockAddrLen = 0;
	int retVal = 0;

	if (udpInfo)
	{
		pSockAddr = &udpInfo->sockaddr;
		sockAddrLen = udpInfo->sockaddrLen;
	}

	retVal = sendto(s, buffer, bufLen, 0, (PSOCKADDR)pSockAddr, sockAddrLen);

	if (retVal == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
	}

	return retVal;
}

LBNET_API int __stdcall UDPReceive(SOCKET s, LPSTR buffer, ULONG bufLen, PLBNetUDPInfo udpInfo)
{
	PSOCKADDR_STORAGE pSockAddr = NULL;
	PINT pSockAddrLen = 0;
	int retVal = 0;

	if (udpInfo)
	{
		pSockAddr = &udpInfo->sockaddr;
		pSockAddrLen = &udpInfo->sockaddrLen;
		*pSockAddrLen = sizeof(SOCKADDR_STORAGE);
	}

	retVal = recvfrom(s, buffer, bufLen, 0, (PSOCKADDR)pSockAddr, pSockAddrLen);

	lastError = WSAGetLastError();

	return retVal;
}

LBNET_API SOCKET __stdcall UDPCreateListenSocket(LPCSTR pService)
{
	return CreateListenSocketInternal(pService, IPPROTO_UDP);
}