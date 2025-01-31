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

LBNET_API SOCKET __stdcall UDPCreateListenSocket(LPCSTR pService)
{
	return CreateListenSocketInternal(NULL, pService, IPPROTO_UDP);
}

LBNET_API SOCKET __stdcall UDPCreateListenSocketOnAddress(LPCSTR pAddress, LPCSTR pService)
{
	return CreateListenSocketInternal(pAddress, pService, IPPROTO_UDP);
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

LBNET_API int _stdcall UDPSetRemoteIP(PLBNetUDPInfo udpInfo, const char* ip, int family)
{
	int retVal = 0;

	udpInfo->sockaddrLen = sizeof(SOCKADDR_STORAGE);

	if (family == AF_INET6)
	{
		PSOCKADDR_IN6 sockAddr = (PSOCKADDR_IN6)&udpInfo->sockaddr;
		sockAddr->sin6_family = AF_INET6;
		retVal = inet_pton(AF_INET6, ip, &sockAddr->sin6_addr);
	}
	else
	{
		PSOCKADDR_IN sockAddr = (PSOCKADDR_IN)&udpInfo->sockaddr;
		sockAddr->sin_family = AF_INET;
		retVal = inet_pton(AF_INET, ip, &sockAddr->sin_addr);
	}

	if (retVal < 0) {
		lastError = WSAGetLastError();
	}

	return retVal;
}

LBNET_API int __stdcall UDPSetRemotePort(PLBNetUDPInfo udpInfo, USHORT port)
{
	USHORT network_port = htons(port);
	((PSOCKADDR_IN)&udpInfo->sockaddr)->sin_port = network_port;
	return 0;
}

LBNET_API int __stdcall UDPGetRemotePort(PLBNetUDPInfo udpInfo)
{
	return ntohs(((PSOCKADDR_IN)&udpInfo->sockaddr)->sin_port);
}


LBNET_API int __stdcall UDPEnableBroadcast(SOCKET s)
{
	BOOL broadcast = TRUE;
	int retVal = setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&broadcast, sizeof(broadcast));
	
	lastError = WSAGetLastError();
	return retVal;
}
