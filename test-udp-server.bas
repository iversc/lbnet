    call OpenLBNetDLL

    input "press ENTER to begin.";a

    hSock = UDPCreateListenSocket("50000")
    if IsSocketInvalid(hSock) then
        print "UDPCreateListenSocket() failed. - ";GetError()
        goto [doEnd]
    end if

    print "UDPCreateListenSocket() - ";hSock

[recvLoop]
    timer 0
    print "Waiting for data..."
    ret = UDPIsReadAvailable(hSock, 0)

    if ret = 0 then
        print "Still waiting..."

        timer 1000, [recvLoop]
        wait
    end if

    [doReceive]

    bufLen = 1024
    buf$ = space$(bufLen)

    recvFrom$ = ""
    num = UDPReceiveFrom(hSock, buf$, bufLen, recvFrom$)

    if num = -1 then
        theError = GetError()
        if theError = 10101 then
            print "Connection closed by server."
        else
            print "Socket error occurred. - ";dechex$(theError)
        end if

        goto [doClose]
    end if

    print "Data - ";left$(buf$, num)

    sendNum = UDPSendTo(hSock, buf$, num, recvFrom$)
    if sendNum = -1 then
        theError = GetError()
        print "UDPSendTo() failed. - ";dechex$(theError)
        goto [doClose]
    end if

    if upper$(left$(buf$, 3)) = "END" then
        print "END command received.  Closing socket."
        goto [doClose]
    end if

    timer 1000, [recvLoop]
    wait

[doClose]
    a = UDPClose(hSock)

[doEnd]
    call CloseLBNetDLL

'====================
'==Helper Functions==
'====================
Sub OpenLBNetDLL
    open "Debug\LBNet.dll" for DLL as #LBNet
    a = InitLBNet()
End Sub

Sub CloseLBNetDLL
    a = EndLBNet()
    close #LBNet
End Sub

Function InitLBNet()
    CallDLL #LBNet, "InitLBNet",_
    InitLBNet as long
End Function

Function EndLBNet()
    CallDLL #LBNet, "EndLBNet",_
    EndLBNet as long
End Function

Function CreateTLSContext()
    CallDLL #LBNet, "CreateTLSContext",_
    CreateTLSContext as ulong
End Function

Function DestroyTLSContext(hTLS)
    CallDLL #LBNet, "DestroyTLSContext",_
    hTLS as ulong,_
    DestroyTLSContext as long
End Function

Function BeginTLSClientNoValidation(hTLS)
    CallDLL #LBNet, "BeginTLSClientNoValidation",_
    hTLS as ulong,_
    BeginTLSClientNoValidation as long
End Function

Function BeginTLSClient(hTLS)
    CallDLL #LBNet, "BeginTLSClient",_
    hTLS as ulong,_
    BeginTLSClient as long
End Function

Function IsSocketInvalid(sock)
    CallDLL #LBNet, "IsSocketInvalid",_
    sock as ulong,_
    IsSocketInvalid as long
End Function

Function BeginTLSServer(hTLS, serverName$)
    CallDLL #LBNet, "BeginTLSServer",_
    hTLS as ulong,_
    serverName$ as ptr,_
    BeginTLSServer as long
End Function

Function SetTLSSocket(hTLS, sock)
    CallDLL #LBNet, "SetTLSSocket",_
    hTLS as ulong,_
    sock as long,_
    SetTLSSock as long
End Function

Function PerformClientHandshake(hTLS, serverName$)
    CallDLL #LBNet, "PerformClientHandshake",_
    hTLS as ulong,_
    serverName$ as ptr,_
    PerformClientHandshake as long
End Function

Function PerformServerHandshake(hTLS, doInitialRead, initBuf$, initBufSize)
    CallDLL #LBNet, "PerformServerHandshake",_
    hTLS as ulong,_
    doInitialRead as long,_
    initBuf$ as ptr,_
    initBufSize as long,_
    PerformServerHandshake as long
End Function

Function CreateListenSocket(pService$)
    CallDLL #LBNet, "CreateListenSocket",_
    pService$ as ptr,_
    CreateListenSocket as ulong
End Function

Function AcceptConnection(ServerSocket)
    CallDLL #LBNet, "AcceptConnection",_
    ServerSocket as ulong,_
    AcceptConnection as ulong
End Function

Function IsReadAvailable(socket, msTimeout)
    CallDLL #LBNet, "IsReadAvailable",_
    socket as ulong,_
    msTimeout as long,_
    IsReadAvailable as long
End Function

Function IsTLSReadAvailable(hTLS, msTimeout)
    CallDLL #LBNet, "IsTLSReadAvailable",_
    hTLS as ulong,_
    msTimeout as long,_
    IsTLSReadAvailable as long
End Function

Function PingHost(host$, packetSize, byref status, byref msResponse, msTimeout)
    struct a, b as long
    struct c, d as long

    a.b.struct = status
    c.d.struct = msResponse

    CallDLL #LBNet, "PingHost",_
    host$ as ptr,_
    packetSize as long,_
    a as struct,_
    c as struct,_
    msTimeout as long,_
    PingHost as long

    status = a.b.struct
    msResponse = c.d.struct
End Function

Function Connect(host$, srv$, msTimeout)
    CallDLL #LBNet, "Connect",_
    host$ as ptr,_
    srv$ as ptr,_
    msTimeout as long,_
    Connect as long
End Function

Function CloseSocket(sock)
    CallDLL #LBNet, "CloseSocket",_
    sock as long,_
    CloseSocket as long
End Function

Function GetError()
    CallDLL #LBNet, "GetError",_
    GetError as long

    if GetError < 0 then
        GetError = (abs(GetError) XOR hexdec("FFFFFFFF")) + 1
    end if
End Function

Function Send(sock, msg$, msgLen)
    CallDLL #LBNet, "Send",_
    sock as long,_
    msg$ as ptr,_
    msgLen as long,_
    Send as long
End Function

Function EncryptSend(hTLS, msg$, msgLen)
    CallDLL #LBNet, "EncryptSend",_
    hTLS as ulong,_
    msg$ as ptr,_
    msgLen as long,_
    EncryptSend as long
End Function

Function Receive(sock, byref buf$, bufLen)
    CallDLL #LBNet, "Receive",_
    sock as long,_
    buf$ as ptr,_
    bufLen as long,_
    Receive as long
End Function

Function DecryptReceive(hTLS, byref buf$, bufLen)
    CallDLL #LBNet, "DecryptReceive",_
    hTLS as ulong,_
    buf$ as ptr,_
    bufLen as long,_
    DecryptReceive as long
End Function

Function EndTLSClientSession(hTLS)
    CallDLL #LBNet, "EndTLSClientSession",_
    hTLS as ulong,_
    EndTLSClientSession as long
End Function

Function UDPConnect(host$, srv$, msTimeout)
    CallDLL #LBNet, "UDPConnect",_
    host$ as ptr,_
    srv$ as ptr,_
    msTimeout as long,_
    UDPConnect as long
End Function

Function UDPSend(sock, buf$, bufLen)
    CallDLL #LBNet, "UDPSend",_
    sock as long,_
    buf$ as ptr,_
    bufLen as long,_
    0 as long,_
    UDPSend as long
End Function

Function UDPSendTo(sock, buf$, bufLen, udpInfo$)
    CallDLL #LBNet, "UDPSend",_
    sock as long,_
    buf$ as ptr,_
    bufLen as long,_
    udpInfo$ as ptr,_
    UDPSend as long
End Function

Function UDPClose(udpSock)
    CallDLL #LBNet, "UDPClose",_
    udpSock as long,_
    UDPClose as long
End Function

Function UDPGetInfoSize()
    CallDLL #LBNet, "UDPGetInfoSize",_
    UDPGetInfoSize as long
End Function

Function UDPReceive(udpSock, byref buf$, bufLen)
    CallDLL #LBNet, "UDPReceive",_
    udpSock as long,_
    buf$ as ptr,_
    bufLen as long,_
    0 as long,_
    UDPReceive as long
End Function

Function UDPReceiveFrom(udpSock, byref buf$, bufLen, byref udpFrom$)
    udpFrom$ = space$(UDPGetInfoSize())

    CallDLL #LBNet, "UDPReceive",_
    udpSock as long,_
    buf$ as ptr,_
    bufLen as long,_
    udpFrom$ as ptr,_
    UDPReceiveFrom as long
End Function

Function UDPIsReadAvailable(udpSock, msTimeout)
    CallDLL #LBNet, "UDPIsReadAvailable",_
    udpSock as long,_
    msTimeout as long,_
    UDPIsReadAvailable as long
End Function

Function UDPCreateListenSocket(pService$)
    CallDLL #LBNet, "UDPCreateListenSocket",_
    pService$ as ptr,_
    UDPCreateListenSocket as long
End Function
