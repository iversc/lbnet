    call OpenLBNetDLL

    input "press ENTER to begin.";a

    connectServer$  = "127.0.0.1"
    hSock = UDPConnect(connectServer$, "50000", 0)
    if IsSocketInvalid(hSock) then
        print "Connect() failed. - ";GetError()
        goto [doEnd]
    end if

    print "UDPConnect() successful."

    data$ = "end"
    lenData = len(data$)

    print "UDPSend() - ";UDPSend(hSock, data$, lenData)

[respLoop]
    timer 0
    print "Waiting for response..."
    ret = UDPIsReadAvailable(hSock, 0)

    if ret = 0 then
        print "Still waiting..."

        timer 1000, [respLoop]
        wait
    end if

[doReceive]

    bufLen = 1024
    buf$ = space$(bufLen)

    num = UDPReceive(hSock, buf$, bufLen)
    theError = GetError()

    if num = -1 then
        if theError = 10101 or theError = 10054 then
            print "Connection closed or reset by peer."
        else
            print "Socket error occurred. - ";theError
        end if

        goto [doClose]
    end if

    'With UDP, if a datagram comes in that is too large for the network stack
    'or the specified buffer to handle, the data will be truncated, and the extra data
    'is lost.  It will still return as many bytes as it can, but it will generate
    'the error code WSAEMSGSIZE(10040) while doing so.
    '
    'While the lost data is unrecoverable, this will at least let the application know
    'something was lost.
    if theError = 10040 then
        print "Received message too large for buffer or other network limit.  Datagram truncated, extra data lost."
    end if

    print "Response - ";left$(buf$, num)

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

Function IsSocketInvalid(sock)
    CallDLL #LBNet, "IsSocketInvalid",_
    sock as ulong,_
    IsSocketInvalid as long
End Function

Function GetError()
    CallDLL #LBNet, "GetError",_
    GetError as long

    if GetError < 0 then
        GetError = (abs(GetError) XOR hexdec("FFFFFFFF")) + 1
    end if
End Function

Function UDPConnect(host$, srv$, msTimeout)
    CallDLL #LBNet, "UDPConnect",_
    host$ as ptr,_
    srv$ as ptr,_
    msTimeout as long,_
    UDPConnect as long
End Function

Function UDPSend(udpSock, buf$, bufLen)
    CallDLL #LBNet, "UDPSend",_
    udpSock as long,_
    buf$ as ptr,_
    bufLen as long,_
    0 as long,_
    UDPSend as long
End Function

Function UDPSendTo(udpSock, buf$, bufLen, udpInfo$)
    CallDLL #LBNet, "UDPSend",_
    udpSock as long,_
    buf$ as ptr,_
    bufLen as long,_
    udpInfo$ as ptr,_
    UDPSendTo as long
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

