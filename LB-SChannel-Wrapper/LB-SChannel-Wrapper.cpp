// LB-SChannel-Wrapper.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include "LB-SChannel-Wrapper.h"

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Ws2_32.lib")

WSADATA wsaData;
ULONG lastError = 0;

#ifdef _DEBUG
HANDLE debugFile = INVALID_HANDLE_VALUE;
#endif

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

DLL_API SOCKET __stdcall CreateListenSocket(LPCSTR pService)
{
	int boundFlag = 0;

	if (pService == NULL)
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

	DWORD dwResult = getaddrinfo(NULL, pService, &hints, &result);
	if (dwResult != 0)
	{
		//getaddrinfo() failed.
		lastError = dwResult;
		WSACleanup();
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
				WSACleanup();
				return INVALID_SOCKET;
			}
		}

		if (bind(s, ptr->ai_addr, ptr->ai_addrlen) != SOCKET_ERROR)
		{
			freeaddrinfo(result);
			boundFlag = 1;
			break;
		}
	}

	if (boundFlag = 0)
	{
		closesocket(s);
		WSACleanup();
		return INVALID_SOCKET;
	}

#ifdef _DEBUG
	WriteDebugLog("Socket bound, now listening...\r\n");
#endif

	if (listen(s, SOMAXCONN) == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
		closesocket(s);
		WSACleanup();
		return INVALID_SOCKET;
	}

	return s;
}

DLL_API SOCKET __stdcall AcceptConnection(SOCKET sock)
{
	SOCKET ClientSocket = accept(sock, NULL, NULL);
	if (ClientSocket == SOCKET_ERROR)
	{
		lastError = WSAGetLastError();
		closesocket(ClientSocket);
		return INVALID_SOCKET;
	}

	return ClientSocket;
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
		WSACleanup();
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
			s = socket(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP);
			if (s == INVALID_SOCKET)
			{
				lastError = WSAGetLastError();
				freeaddrinfo(result);
				WSACleanup();
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
				WSACleanup();
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
	WSACleanup();
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


DLL_API BOOL __stdcall IsReadAvailable(SOCKET sock, int msTimeout)
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

