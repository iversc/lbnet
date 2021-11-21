#include "stdafx.h"
#include "LBNet.h"

#define IPADDR_BUF_SIZE INET6_ADDRSTRLEN  //46 character string needed to hold an IPv6 address
char ipAddrBuf[IPADDR_BUF_SIZE];

LBNET_API SOCKET __stdcall UDPConnect(LPCSTR pHost, LPCSTR pService, ULONG msTimeout)
{
	return ConnectInternal(pHost, pService, msTimeout, NULL, IPPROTO_UDP);
}

LBNET_API SOCKET __stdcall UDPConnectFrom(LPCSTR pHost, LPCSTR pService, ULONG msTimeout, LPCSTR pLocalService)
{
	return ConnectInternal(pHost, pService, msTimeout, pLocalService, IPPROTO_UDP);
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

LBNET_API SOCKET __stdcall UDPCreateListenSocket(LPCSTR address, LPCSTR pService)
{
	return CreateListenSocketInternal(address, pService, IPPROTO_UDP);
}

LBNET_API LPCSTR __stdcall UDPGetRemoteIP(PLBNetUDPInfo udpInfo)
{
	ZeroMemory(ipAddrBuf, IPADDR_BUF_SIZE);
	PCSTR retVal = NULL;

	if (udpInfo->sockaddr.ss_family == AF_INET6)
	{
		PSOCKADDR_IN6 sockAddr = (PSOCKADDR_IN6)&udpInfo->sockaddr;
		retVal = inet_ntop(AF_INET6, &sockAddr->sin6_addr, ipAddrBuf, IPADDR_BUF_SIZE);
	}
	else
	{
		PSOCKADDR_IN sockAddr = (PSOCKADDR_IN)&udpInfo->sockaddr;
		retVal = inet_ntop(AF_INET, &sockAddr->sin_addr, ipAddrBuf, IPADDR_BUF_SIZE);
	}

	lastError = WSAGetLastError();

	return retVal;
}

LBNET_API int __stdcall UDPGetRemotePort(PLBNetUDPInfo udpInfo)
{
	return ntohs(((PSOCKADDR_IN)&udpInfo->sockaddr)->sin_port);
}
