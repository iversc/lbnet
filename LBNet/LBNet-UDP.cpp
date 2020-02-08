#include "stdafx.h"
#include "LBNet.h"

LBNET_API SOCKET __stdcall UDPConnect(LPCSTR pHost, LPCSTR pService, ULONG msTimeout)
{
	return ConnectInternal(pHost, pService, msTimeout, IPPROTO_UDP);
}

LBNET_API UINT __stdcall GetUDPInfoSize()
{
	return sizeof(LBNetUDPInfo);
}

LBNET_API int __stdcall UDPSend(SOCKET s, LPCSTR buffer, ULONG bufLen, PLBNetUDPInfo udpInfo)
{
	PSOCKADDR_STORAGE pSockAddr = NULL;
	int sockAddrLen = 0;

	if (udpInfo)
	{
		pSockAddr = &udpInfo->sockaddr;
		sockAddrLen = udpInfo->sockaddrLen;
	}

	int retVal = sendto(s, buffer, bufLen, 0, (PSOCKADDR)pSockAddr, sockAddrLen);

	if (retVal == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
	}

	return retVal;
}