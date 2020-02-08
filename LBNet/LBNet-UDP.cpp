#include "stdafx.h"
#include "LBNet.h"

LBNET_API PLBNetUDPSocket __stdcall UDPConnect(LPCSTR pHost, LPCSTR pService, ULONG msTimeout)
{
	return (PLBNetUDPSocket)ConnectInternal(pHost, pService, msTimeout, IPPROTO_UDP);
}

LBNET_API UINT __stdcall UDPGetInfoSize()
{
	return sizeof(LBNetUDPInfo);
}

LBNET_API int __stdcall UDPSend(PLBNetUDPSocket udpSock, LPCSTR buffer, ULONG bufLen, PLBNetUDPInfo udpInfo)
{
	PSOCKADDR_STORAGE pSockAddr = NULL;
	int sockAddrLen = 0;

	if (udpInfo)
	{
		pSockAddr = &udpInfo->sockaddr;
		sockAddrLen = udpInfo->sockaddrLen;
	}
	else
	{
		pSockAddr = &udpSock->udpInfo.sockaddr;
		sockAddrLen = udpSock->udpInfo.sockaddrLen;
	}

	int retVal = sendto(udpSock->s, buffer, bufLen, 0, (PSOCKADDR)pSockAddr, sockAddrLen);

	if (retVal == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
	}

	return retVal;
}

LBNET_API int __stdcall UDPReceive(PLBNetUDPSocket udpSock, LPSTR buffer, ULONG bufLen, PLBNetUDPInfo udpInfo)
{
	PSOCKADDR_STORAGE pSockAddr = NULL;
	PINT pSockAddrLen = 0;

	if (udpInfo)
	{
		pSockAddr = &udpInfo->sockaddr;
		pSockAddrLen = &udpInfo->sockaddrLen;
		*pSockAddrLen = sizeof(SOCKADDR_STORAGE);
	}

	int retVal = recvfrom(udpSock->s, buffer, bufLen, 0, (PSOCKADDR)pSockAddr, pSockAddrLen);
	
	if (retVal == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
	}

	return retVal;
}

LBNET_API int __stdcall UDPClose(PLBNetUDPSocket udpSock)
{
	int retVal = closesocket(udpSock->s);
	delete udpSock;

	return retVal;
}

LBNET_API BOOL __stdcall UDPIsReadAvailable(PLBNetUDPSocket udpSock, int msTimeout)
{
	return IsReadAvailable(udpSock->s, msTimeout);
}

LBNET_API PLBNetUDPSocket __stdcall UDPCreateListenSocket(LPCSTR pService)
{
	PLBNetUDPSocket udpSock = new LBNetUDPSocket();

	udpSock->s = CreateListenSocketInternal(pService, IPPROTO_UDP);

	return udpSock;
}