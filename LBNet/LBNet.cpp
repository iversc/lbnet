// LB-SChannel-Wrapper.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <IcmpAPI.h>
#include <stdio.h>
#include <stdlib.h>
#include "LBNet.h"

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")

WSADATA wsaData;
ULONG lastError = 0;

enum Protocol {TCP, UDP};

#ifdef _DEBUG
HANDLE debugFile = INVALID_HANDLE_VALUE;
#endif

#ifdef _DEBUG
void WriteDebugLog(LPCSTR function, LPCSTR message)
{
	debugFile = CreateFile("wrapperdebug.log", FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (debugFile != INVALID_HANDLE_VALUE)
	{
		DWORD msgLen = strlen(function) + strlen(message) + 10;
		char * fullMsg = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, msgLen);
		DWORD outSize = snprintf(fullMsg, msgLen, "%s, %s\r\n", function, message);
		DWORD written = 0;
		WriteFile(debugFile, fullMsg, outSize, &written, NULL);
		CloseHandle(debugFile);
		HeapFree(GetProcessHeap(), 0, fullMsg);
		debugFile = INVALID_HANDLE_VALUE;
	}
}
#endif

LBNET_API ULONG __stdcall GetError()
{
	return lastError;
}

LBNET_API int __stdcall InitLBNet()
{
	//Initialize Winsock.
#ifdef _DEBUG
	WriteDebugLog("InitLBNet", "DLL init");
#endif
	lastError = WSAStartup(MAKEWORD(2, 2), &wsaData);
	return lastError;
}

LBNET_API int __stdcall EndLBNet()
{
#ifdef _DEBUG
	WriteDebugLog("EndLBNet", "DLL term");
#endif

	int iResult = WSACleanup();
	lastError = WSAGetLastError();
	return iResult;
}

LBNET_API SOCKET __stdcall CreateListenSocket(LPCSTR pService)
{
	int boundFlag = 0;

	if (pService == NULL)
	{
		lastError = ERROR_INVALID_PARAMETER;
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
	hints.ai_flags = AI_PASSIVE;

	addrinfo * result = NULL;
	addrinfo * ptr = NULL;

	DWORD dwResult = getaddrinfo(NULL, pService, &hints, &result);
	if (dwResult != 0)
	{
		//getaddrinfo() failed.
		lastError = dwResult;
		return INVALID_SOCKET;
	}

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
				lastError = WSAGetLastError();
				freeaddrinfo(result);
				return INVALID_SOCKET;
			}
		}

		if (bind(s, ptr->ai_addr, ptr->ai_addrlen) != SOCKET_ERROR)
		{
			boundFlag = 1;
		}
	}

	if (boundFlag == 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	freeaddrinfo(result);

	if (listen(s, SOMAXCONN) == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

LBNET_API SOCKET __stdcall AcceptConnection(SOCKET sock, LPSTR buffer, ULONG bufLen)
{
	socklen_t len;
	struct sockaddr_storage addr;

	len = sizeof addr;
	SOCKET ClientSocket = accept(sock, (struct sockaddr*)&addr, &len);

	// deal with both IPv4 and IPv6:
	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		inet_ntop(AF_INET, &s->sin_addr, buffer, bufLen);
	}
	else { // AF_INET6
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		inet_ntop(AF_INET6, &s->sin6_addr, buffer, bufLen);
	}

	if (ClientSocket == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
		closesocket(ClientSocket);
		return INVALID_SOCKET;
	}

	return ClientSocket;
}

LBNET_API SOCKET __stdcall Connect(LPCSTR pHost, LPCSTR pService, ULONG msTimeout)
{
	return ConnectInternal(pHost, pService, msTimeout, IPPROTO_TCP);
}

SOCKET ConnectInternal(LPCSTR pHost, LPCSTR pService, ULONG msTimeout, int protocol)
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

	int socktype = (protocol == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;

	//Hints are used to tell getaddrinfo() what kind of socket we're intending to use
	//You can specify family(IPv4, IPv6, UNIX, Unspecified/any, etc),
	//socket type(stream or datagram, basically connection-oriented(TCP) or connectionless(UDP)),
	//and protocol(TCP, UDP, RAW, etc).
    //
	//The options we use here are going to be TCP/stream, with unspecified socket family, so
	//we can connect to either IPv4 or IPv6 servers without changing code.
	addrinfo hints = addrinfo();
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = socktype;
	hints.ai_protocol = protocol;

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
		tv.tv_usec = (msTimeout % 1000) * 1000;
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
			s = socket(AF_UNSPEC, socktype, protocol);
			if (s == INVALID_SOCKET)
			{
				lastError = WSAGetLastError();
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

LBNET_API int __stdcall Send(SOCKET s, LPCSTR buffer, ULONG bufLen)
{
	int retVal = send(s, buffer, bufLen, 0);
	if (retVal == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
	}

	return retVal;
}

LBNET_API int __stdcall Receive(SOCKET s, LPSTR buffer, ULONG bufLen)
{
	int retVal = recv(s, buffer, bufLen, 0);
	if (retVal == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
	}

	return retVal;
}

LBNET_API BOOL __stdcall IsSocketInvalid(SOCKET sock)
{
	return sock == INVALID_SOCKET;
}

LBNET_API ULONG __stdcall CloseSocket(SOCKET sock)
{
	return closesocket(sock);
}


LBNET_API BOOL __stdcall IsReadAvailable(SOCKET sock, int msTimeout)
{
	if (sock == INVALID_SOCKET) {
		lastError = INVALID_SOCKET;
		return SOCKET_ERROR;
	}
	
	fd_set set;
	FD_ZERO(&set);
	FD_SET(sock, &set);

	//Passing in a valid TIMEVAL of time zero means instant, non-blocking return.
	TIMEVAL tv = { 0,0 };

	if (msTimeout > 0)
	{
		tv.tv_sec = msTimeout / 1000;
		tv.tv_usec = (msTimeout % 1000) * 1000;
	}

	if (select(0, &set, NULL, NULL, &tv) == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
		return SOCKET_ERROR;
	}

	if(FD_ISSET(sock, &set))
	{
		lastError = 0;
		return 1;
	}

	lastError = 0;
	return 0;
}

LBNET_API int __stdcall PingHost(LPCSTR host, UINT PktSize, int * status, int * msReply, int msTimeout)
{
	if (host == NULL || status == NULL || msReply == NULL || PktSize == NULL)
	{
		lastError = ERROR_INVALID_PARAMETER;
		return INVALID_SOCKET;
	}

	addrinfo hints = addrinfo();
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	addrinfo * result = NULL;
	addrinfo * ptr = NULL;

	//Attempt to auto-build a SOCKADDR structure, whether it's IPv4 or IPv6
	DWORD dwResult = getaddrinfo(host, "80", &hints, &result);
	if (dwResult != 0)
	{
		//getaddrinfo() failed.
		lastError = dwResult;
		return INVALID_SOCKET;
	}

	if (result == NULL) {
		return INVALID_SOCKET;
	}

	// Create request data to use
	UINT n;
	char* requestData;

	requestData = (char*)malloc(PktSize);

	if (requestData == NULL)
	{
		lastError = ERROR_OUTOFMEMORY;
		return INVALID_SOCKET;
	}

	for (n = 0; n < PktSize; n++)
		requestData[n] = rand() % 26 + 'a';

	//If we have an IPv4 result, use IcmpSendEcho().
	if (result->ai_family == AF_INET)
	{
		//Convert the generic sockaddr structure from the returned info
		//to an IPv4-specific one
		PSOCKADDR_IN addr = reinterpret_cast<PSOCKADDR_IN>(result->ai_addr);
		
		HANDLE icmp = IcmpCreateFile();
		if (icmp == INVALID_HANDLE_VALUE)
		{
			freeaddrinfo(result);
			return INVALID_SOCKET;
		}

		// Calculate response buffer size.
		//
		// Documented as needing to be the size of one ICMP_ECHO_REPLY structure,
		// plus the size of the request data, PLUS 8 extra bytes to cover ICMP errors.
		int responseBufSize = sizeof(ICMP_ECHO_REPLY) + PktSize + 8;

		// Create response buffer.
		PVOID responseBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, responseBufSize);

		if (responseBuf == NULL)
		{
			lastError = ERROR_OUTOFMEMORY;
			return INVALID_SOCKET;
		}

		if (IcmpSendEcho(icmp, addr->sin_addr.S_un.S_addr, (LPVOID)requestData, PktSize, NULL,
			responseBuf, responseBufSize, msTimeout) == 0)
		{
			free(requestData);
			freeaddrinfo(result);
			HeapFree(GetProcessHeap(), 0, responseBuf);
			IcmpCloseHandle(icmp);
			lastError = GetLastError();
			return INVALID_SOCKET;
		}

		PICMP_ECHO_REPLY rep = (PICMP_ECHO_REPLY)responseBuf;
		*status = rep->Status;
		*msReply = rep->RoundTripTime;

		free(requestData);
		HeapFree(GetProcessHeap(), 0, responseBuf);
		freeaddrinfo(result);
		IcmpCloseHandle(icmp);
		return 0;
	}
	else if (result->ai_family == AF_INET6)
	{
		//Convert the generic sockaddr structure from the returned info
		//to an IPv6-specific one
		PSOCKADDR_IN6 addr = reinterpret_cast<PSOCKADDR_IN6>(result->ai_addr);

		HANDLE icmp = Icmp6CreateFile();
		if (icmp == INVALID_HANDLE_VALUE)
		{
			freeaddrinfo(result);
			return INVALID_SOCKET;
		}

		sockaddr_in6 saSource;
		saSource.sin6_family = AF_INET6;
		saSource.sin6_addr = in6addr_any;
		saSource.sin6_flowinfo = 0;
		saSource.sin6_port = 0;

		// Calculate response buffer size.
		//
		// Documented as needing to be the size of one ICMPV6_ECHO_REPLY structure,
		// plus the size of the request data, PLUS 8 extra bytes to cover ICMP errors
		int responseBufSize = sizeof(ICMPV6_ECHO_REPLY) + PktSize + 8;

		// Create response buffer.
		PVOID responseBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, responseBufSize);

		if (responseBuf == NULL)
		{
			lastError = ERROR_OUTOFMEMORY;
			return INVALID_SOCKET;
		}

		if (Icmp6SendEcho2(icmp, NULL, NULL, NULL, &saSource, addr, (LPVOID)requestData,
			PktSize, NULL, responseBuf, responseBufSize, msTimeout) == 0)
		{
			free(requestData);
			freeaddrinfo(result);
			HeapFree(GetProcessHeap(), 0, responseBuf);
			IcmpCloseHandle(icmp);
			lastError = GetLastError();
			return INVALID_SOCKET;
		}

		if (Icmp6ParseReplies(responseBuf, responseBufSize) == 0)
		{
			free(requestData);
			freeaddrinfo(result);
			HeapFree(GetProcessHeap(), 0, responseBuf);
			IcmpCloseHandle(icmp);
			lastError = GetLastError();
			return INVALID_SOCKET;
		}

		PICMPV6_ECHO_REPLY rep = (PICMPV6_ECHO_REPLY)responseBuf;
		*status = rep->Status;
		*msReply = rep->RoundTripTime;

		free(requestData);
		HeapFree(GetProcessHeap(), 0, responseBuf);
		freeaddrinfo(result);
		IcmpCloseHandle(icmp);
		return 0;
	}
    
	return INVALID_SOCKET;
}
