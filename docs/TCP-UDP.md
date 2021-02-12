# LBNet API Reference
This is an overall reference to the LBNet communications library. The library supports communication over TCP and UDP sockets, as well as TLS-secured TCP connections.

This doc covers basic sockets usage, in both TCP and UDP. The other doc included covers TLS usage. You should be familiar with everything in this doc before attempting TLS communications.

---

## Table of Contents
- [LBNet API Reference](#lbnet-api-reference)
  - [Table of Contents](#table-of-contents)
  - [API Functions Index](#api-functions-index)
    - [**General Functions**](#general-functions)
      - [**`CloseLBNetDLL`**](#closelbnetdll)
      - [**`EndLBNet()`**](#endlbnet)
      - [**`GetError()`**](#geterror)
      - [**`GetErrorText$(errnum)`**](#geterrortexterrnum)
      - [**`InitLBNet()`**](#initlbnet)
      - [**`IsSocketInvalid(sock)`**](#issocketinvalidsock)
      - [**`OpenLBNetDLL`**](#openlbnetdll)
      - [**`PingHost(host$, packetSize, byref status, byref msResponse, msTimeout)`**](#pinghosthost-packetsize-byref-status-byref-msresponse-mstimeout)
    - [**TCP Functions**](#tcp-functions)
      - [**`AcceptConnection(ServerSocket)`**](#acceptconnectionserversocket)
      - [**`CloseSocket(sock)`**](#closesocketsock)
      - [**`Connect(host$, srv$, msTimeout)`**](#connecthost-srv-mstimeout)
      - [**`ConnectFrom(host$, srv$, msTimeout, localSrv$)`**](#connectfromhost-srv-mstimeout-localsrv)
      - [**`CreateListenSocket(pService$)`**](#createlistensocketpservice)
      - [**`IsReadAvailable(socket, msTimeout)`**](#isreadavailablesocket-mstimeout)
      - [**`Receive(sock, byref buf$, bufLen)`**](#receivesock-byref-buf-buflen)
      - [**`Send(sock, msg$, msgLen)`**](#sendsock-msg-msglen)
    - [**UDP Functions**](#udp-functions)
      - [**`UDPClose(udpSock)`**](#udpcloseudpsock)
      - [**`UDPConnect(host$, srv$, msTimeout)`**](#udpconnecthost-srv-mstimeout)
      - [**`UDPConnectFrom(host$, srv$, msTimeout, localSrv$)`**](#udpconnectfromhost-srv-mstimeout-localsrv)
      - [**`UDPCreateListenSocket(pService$)`**](#udpcreatelistensocketpservice)
      - [**`UDPGetInfoSize()`**](#udpgetinfosize)
      - [**`UDPGetRemoteIP$(udpInfo$)`**](#udpgetremoteipudpinfo)
      - [**`UDPGetRemotePort(udpInfo$)`**](#udpgetremoteportudpinfo)
      - [**`UDPIsReadAvailable(udpSock, msTimeout)`**](#udpisreadavailableudpsock-mstimeout)
      - [**`UDPReceive(udpSock, byref buf$, bufLen)`**](#udpreceiveudpsock-byref-buf-buflen)
      - [**`UDPReceiveFrom(udpSock, byref buf$, bufLen, byref udpFrom$)`**](#udpreceivefromudpsock-byref-buf-buflen-byref-udpfrom)
      - [**`UDPSend(udpSock, buf$, bufLen)`**](#udpsendudpsock-buf-buflen)
      - [**`UDPSendTo(udpSock, buf$, bufLen, udpInfo$)`**](#udpsendtoudpsock-buf-buflen-udpinfo)


---

## API Functions Index
This section is a listing of the functions provided by the library, and their usage. The functions are in alphabetical order.

---
### **General Functions**
Functions in this section either relate to both TCP and UDP communications, or are specific to the LBNet library.



#### **`CloseLBNetDLL`**
A helper subroutine for terminating and closing the LBNet library. Use in conjunction with [`OpenLBNetDLL`](#openlbnetdll). This will automatically call the [`EndLBNet()`](#endlbnet) function to clean up, and then will close the handle to the LBNet library(`close #LBNet`).

##### Parameters: <!-- omit in toc -->
None.

##### Return value: <!-- omit in toc -->
None, this is a `SUB` invoked with the `call` statement.

```
call CloseLBNetDLL
```


#### **`EndLBNet()`**
Runs cleanup for all LBNet library data. Must be the last thing called before closing the library.

##### Parameters: <!-- omit in toc -->
None.

##### Return value: <!-- omit in toc -->
Zero if termination is successful, and `SOCKET_ERROR(-1)` otherwise. The error code can be retrieved with [`GetError()`](#geterror).



#### **`GetError()`**
Retrieves the last error code set by the LBNet library.

##### Parameters: <!-- omit in toc -->
None.

##### Return value: <!-- omit in toc -->
The last error code set by the LBNet library.



#### **`GetErrorText$(errnum)`**
Retrieves a descriptive error message for the error code specified.

##### Parameters: <!-- omit in toc -->
`errnum`: The error code for which a textual message is needed, most likely returned from [`GetError()`](#geterror).

##### Return value: <!-- omit in toc -->
A string containing the error message that corresponds to the error code specified.



#### **`InitLBNet()`**
Initializes the LBNet library. Must be the first thing called.

##### Parameters: <!-- omit in toc -->
None

##### Return value: <!-- omit in toc -->
Zero if initialization is successful, and an error code otherwise. The error message can be retrieved with [`GetErrorText$()`](#geterrortexterrnum).



#### **`IsSocketInvalid(sock)`**
Checks whether or not the specified socket value is `INVALID_SOCKET`.

The reason this function exists is because of LB's flexibility with types. `INVALID_SOCKET` is declared as -1, but because the only valid socket values are positive, the types of all sockets in my functions are declared as unsigned.

This causes confusion with LB when returning `INVALID_SOCKET`, and causes it to intepret the signed (-1) as the unsigned (0xFFFFFFFF).

When checking returns from functions that return sockets, you can either check them against 0xFFFFFFFF, or call this function with the value.

##### Parameters: <!-- omit in toc -->
`sock`: A socket or server/listen socket returned from [`Connect()`](#connecthost-srv-mstimeout), [`ConnectFrom()`](#connectfromhost-srv-mstimeout-localsrv), [`CreateListenSocket()`](#createlistensocketpservice), [`UDPConnect()`](#udpconnecthost-srv-mstimeout), [`UDPConnectFrom()`](#udpconnectfromhost-srv-mstimeout-localsrv), or [`UDPCreateListenSocket()`](#udpcreatelistensocketpservice).

##### Return value: <!-- omit in toc -->
One(1) if the specified socket is `INVALID_SOCKET`, zero(0) otherwise.



#### **`OpenLBNetDLL`**
A helper subroutine for opening and initializing the LBNet library. Use in conjunction with [`CloseLBNetDLL`](#closelbnetdll). This will automatically open a handle to the LBNet library(`open "LBNet.dll" for DLL as #LBNet`), and call the [`InitLBNet()`](#initlbnet) function to initialize LBNet.

##### Parameters: <!-- omit in toc -->
None.

##### Return value: <!-- omit in toc -->
None, this is a `SUB` invoked with the `call` statement.

```
call OpenLBNetDLL
```



#### **`PingHost(host$, packetSize, byref status, byref msResponse, msTimeout)`**
Initiates a ping(ICMP_ECHO) request towards the specified host.

##### Parameters: <!-- omit in toc -->
`host$`: The IP address or hostname of the device to ping.

`packetSize`: The number of bytes to use to send a ping message with. Must be greater than zero.

`status`: Used as a return value.

`msResponse`: Used as a return value.

`msTimeout`: Amount of time(in milliseconds) to wait for ping response before giving up.

##### Return values: <!-- omit in toc -->
Zero if ping request successfully sent, `SOCKET_ERROR(-1)` otherwise.

**Note:** This does _not_ indicate if the target host replied! It only indicates if a ping was successfully _sent_!  The `status` parameter must be checked for successful reply.

`status`: This will have a value of zero(`IP_SUCCESS`) the target host replied, or a different code otherwise. Possible codes are documented in the [Win32 API here](https://docs.microsoft.com/en-us/windows/win32/api/ipexport/ns-ipexport-icmp_echo_reply).

`msResponse`: The round-trip time(in milliseconds) of the ping, if the target host replied.

---
### **TCP Functions**
Functions in this section are used for TCP communications.



#### **`AcceptConnection(ServerSocket)`**
Accepts a waiting connection from a listening server/listen socket.

**Note:** If there is not a connection waiting, this function will block until a connection is received. Use [`IsReadAvailable()`](#isreadavailablesocket-mstimeout) to check if connections are waiting to prevent blocking.

##### Parameters: <!-- omit in toc -->
`ServerSocket`: A listen socket/server socket returned from [`CreateListenSocket()`](#createlistensocketpservice).

##### Return value: <!-- omit in toc -->
A valid `socket` connection to the client, or `INVALID_SOCKET(0xFFFFFFFF)`. If `INVALID_SOCKET` is received, you can call [`GetError()`](#geterror) to get a specific error code.



#### **`CloseSocket(sock)`**
Closes an opened socket or server/listen socket.

##### Parameters: <!-- omit in toc -->
`sock`: A socket or server/listen socket, returned from [`Connect()`](#connecthost-srv-mstimeout), [`ConnectFrom()`](#connectfromhost-srv-mstimeout-localsrv), or [`CreateListenSocket()`](#createlistensocketpservice).

##### Return value: <!-- omit in toc -->
Zero(0) if the socket was closed successfully, or `SOCKET_ERROR(-1)` if an error occurs. If an error occurs, [`GetError()`](#geterror) can be called to retrieve a specific error code.



#### **`Connect(host$, srv$, msTimeout)`**
#### **`ConnectFrom(host$, srv$, msTimeout, localSrv$)`**
Opens a socket connection to the specified host and port. `ConnectFrom()` additionally allows selection of the local port to send from.

##### Parameters: <!-- omit in toc -->
`host$`: The IP address or hostname of the server to connect to.

`srv$`: The port number(e.g. "80") or service name(e.g. "http") to connect to, specified as a string.

`msTimeout`: Optional, can be zero. Specifies an amount of time to wait for the connection to succeed. If zero is specified, default timeout of the system's network stack is used.

`localSrv$`: Same syntax as `srv$`, specifies a port number or service name to connect _from_.

##### Return value: <!-- omit in toc -->
A valid socket connection to the specified server/port, or `INVALID_SOCKET(0xFFFFFFFF)`. If `INVALID_SOCKET` is returned, [`GetError()`](#geterror) can be called to retrieve a specific error code.



#### **`CreateListenSocket(pService$)`**
Creates a server/listen socket to listen for connections on the specified port.

##### Parameters: <!-- omit in toc -->
`pService$`: The port number(e.g. "80") or service name(e.g. "http") to listen on, specified as a string.

##### Return value: <!-- omit in toc -->
A valid server/listen socket, waiting for connections on the specified port, or `INVALID_SOCKET(0xFFFFFFFF)`. If `INVALID_SOCKET` is received, you can call [`GetError()`](#geterror) to retrieve a more specific error code.



#### **`IsReadAvailable(socket, msTimeout)`**
Checks if the specified socket has received data that can be retrieved, or if a server/listen socket has connections that can be accepted. Will wait the number of milliseconds specified before returning.

##### Parameters: <!-- omit in toc -->

`socket`: A socket or server/listen socket to check for waiting data/connections.

`msTimeout`: Amount of time to wait for data/connections, specified in milliseconds. If zero, the function will return immediately.

##### Return value: <!-- omit in toc -->
One(1) if data/connections are available, zero(0) otherwise.



#### **`Receive(sock, byref buf$, bufLen)`**
Retrieve data from the specified socket.

**Note:** If there is no data waiting to be received from the socket, this function will block until more data arrives. Use the [`IsReadAvailable()`](#isreadavailablesocket-mstimeout) function to check if there's data available before calling `Receive()` to prevent blocking.

##### Parameters: <!-- omit in toc -->
`sock`: A connected socket, returned from [`AcceptConnection()`](#acceptconnectionserversocket), [`Connect()`](#connecthost-srv-mstimeout), or [`ConnectFrom()`](#connectfromhost-srv-mstimeout-localsrv).

`buf$`: A buffer that the retrieved data gets written to.

`bufLen`: The size of the buffer(in bytes) specified in `buf$`.

##### Return value: <!-- omit in toc -->
Returns the number of bytes written to `buf$`.

If this number is zero, this indicates that the connected host has closed the connection on their end. In this case, this socket should be closed with [`CloseSocket()`](#closesocketsock).

If there is an error retrieving data, this return value will be `SOCKET_ERROR(-1)`. In such a case, you can call [`GetError()`](#geterror) to retrieve a specific error code.



#### **`Send(sock, msg$, msgLen)`**
Tramsmits the specified data to the connected host.

##### Parameters: <!-- omit in toc -->
`sock`: The socket used to send the data.

`msg$`: The data to be sent over the socket.

`msgLen`: The size(in bytes) of the data to send.

##### Return value: <!-- omit in toc -->
Returns the number of bytes sent to the connected socket.

**Note:** It is possible for this to be less than the amount of bytes in `msg$`! This is not an error condition, and if less bytes have been sent, it is up to the program to attempt retransmission of the data that has yet to be sent.

If an error occurs in transmission, `SOCKET_ERROR(-1)` will be returned, and [`GetError()`](#geterror) can be called to retrieve a specific error code.

---
### **UDP Functions**
The functions past this point are used for UDP connections. Most of these are directly equivalent to their TCP versions, and will link to those versions for full behavior details.

Anything that's different for UDP will be listed here.

#### **`UDPClose(udpSock)`**
This function is the UDP equivalent of [`CloseSocket()`](#closesocketsock), and is used the same way.

It is used for UDP sockets returned from [`UDPConnect()`](#udpconnecthost-srv-mstimeout), [`UDPConnectFrom()`](#udpconnectfromhost-srv-mstimeout-localsrv), and [`UDPCreateListenSocket()`](#udpcreatelistensocketpservice).



#### **`UDPConnect(host$, srv$, msTimeout)`**
#### **`UDPConnectFrom(host$, srv$, msTimeout, localSrv$)`**
These functions are the UDP equivalents of [`Connect()`](#connecthost-srv-mstimeout) and [`ConnectFrom()`](#connectfromhost-srv-mstimeout-localsrv).



#### **`UDPCreateListenSocket(pService$)`**
This function is the UDP equivalent of [`CreateListenSocket()`](#createlistensocketpservice).

The primary difference is, instead of listening for and acceping connections, data is sent and received directly to/from the returned socket using the [`UDPSendTo()`](#udpsendtoudpsock-buf-buflen-udpinfo) and [`UDPReceiveFrom()`](#udpreceivefromudpsock-byref-buf-buflen-byref-udpfrom) functions.



#### **`UDPGetInfoSize()`**
This function retrives the size of the data blob used by [`UDPReceiveFrom()`](#udpreceivefromudpsock-byref-buf-buflen-byref-udpfrom) and [`UDPSendTo()`](#udpsendtoudpsock-buf-buflen-udpinfo) that identifies the other side of the connection. This function is called by [`UDPReceiveFrom()`](#udpreceivefromudpsock-byref-buf-buflen-byref-udpfrom) directly to make a proper buffer for the data blob; it is unlikely to be used by a program directly.

##### Parameters: <!-- omit in toc -->
None.

##### Return value: <!-- omit in toc -->
Size of the UDP data blob, in bytes.



#### **`UDPGetRemoteIP$(udpInfo$)`**
Gets the IP address from a UDP data blob.

##### Parameters: <!-- omit in toc -->
`udpInfo$`: UDP data blob returned from [`UDPReceiveFrom()`](#udpreceivefromudpsock-byref-buf-buflen-byref-udpfrom)

##### Return value: <!-- omit in toc -->
A string containing the IP address of the connected peer.



#### **`UDPGetRemotePort(udpInfo$)`**
Gets the port number from a UDP data blob.

##### Parameters: <!-- omit in toc -->
`udpInfo$`: UDP data blob returned from [`UDPReceiveFrom()`](#udpreceivefromudpsock-byref-buf-buflen-byref-udpfrom)

##### Return value: <!-- omit in toc -->
A the port number of the connected peer.



#### **`UDPIsReadAvailable(udpSock, msTimeout)`**
This function is the UDP equivalent of [`IsReadAvailable()`](#isreadavailablesocket-mstimeout).



#### **`UDPReceive(udpSock, byref buf$, bufLen)`**
This function is the UDP equivalent of [`Send()`](#sendsock-msg-msglen).

**Important:** This function can only be used on client UDP sockets returned from [`UDPConnect()`](#udpconnecthost-srv-mstimeout) and [`UDPConnectFrom()`](#udpconnectfromhost-srv-mstimeout-localsrv). To receive data from UDP server/listen sockets created with [`UDPCreateListenSocket()`](#udpcreatelistensocketpservice), you _must_ use the function [`UDPReceiveFrom()`](#udpreceivefromudpsock-byref-buf-buflen-byref-udpfrom).



#### **`UDPReceiveFrom(udpSock, byref buf$, bufLen, byref udpFrom$)`**
#### **`UDPSend(udpSock, buf$, bufLen)`**
#### **`UDPSendTo(udpSock, buf$, bufLen, udpInfo$)`**

