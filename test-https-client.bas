    call OpenTLSDLL

    input "press ENTER to begin.";a

    connectServer$  = "www.jmarshall.com"
    hSock = Connect(connectServer$, "https", 0)
    if IsSocketInvalid(hSock) then
        print "Connect() failed. - ";GetError()
        goto [doEnd]
    end if

    print "Connect() successful."

[beginTLS]

    print "Creating TLS context..."
    hTLS = CreateTLSContext()

    print "Acquiring TLS credentials..."
    ret = BeginTLSClient(hTLS)
    if ret <> 0 then
        print "BeginTLSClient() failed. ret - ";ret;" -- Error - ";GetError()
        Print dechex$( (abs(ret) XOR hexdec("FFFFFFFF")) + 1)
        a = DestroyTLSContext(hTLS)
        goto [doSockEnd]
    end if

    Print "Finishing connection..."

[handshakeLoop]

    a = SetTLSSocket(hTLS, hSock)

    ret = PerformClientHandshake(hTLS, connectServer$)
    if ret <> 0 then
        print "PerformClientHandshake() failed. - ";ret; " - Error: ";dechex$(GetError())
        Print dechex$( (abs(ret) XOR hexdec("FFFFFFFF")) + 1)
        a = CloseSocket(hSock)
        a = DestroyTLSContext(hTLS)
        goto [doSockEnd]
    end if

    crlf$ = chr$(13) + chr$(10)

    request$ = "GET /easy/http/ HTTP/1.1" + crlf$
    request$ = request$ + "Host: " + connectServer$ + crlf$
    request$ = request$ + crlf$

    print
    print "REQUEST"
    print request$
    print "======="
    print
    print "Sending request to server..."

    lenRequest = len(request$)
    ret = EncryptSend(hTLS, request$, lenRequest)

    Print "Awaiting server response..."
[bufLoop]
    timer 0
    if TLSActive then
        ret = IsTLSReadAvailable(hTLS, 0)
    end if

    if ret = 0 then
        'No data waiting.  Stop and wait.
        timer 1, [bufLoop]
        wait
    end if

    bufLen = 1024
    buf$ = space$(bufLen)
    num = DecryptReceive(hTLS, buf$, bufLen)

    If num = -1 then
        theError = GetError()
        if theError = 10101 then
            print "Connection closed by server."
            if HeadersComplete then goto [contentComplete]
        else
            Print "Socket error occurred. - ";dechex$(GetError())
        end if
        a = CloseSocket(hSock)
        a = DestroyTLSContext(hTLS)
        goto [doEnd]
    End if

    If HeadersComplete then
        buf$ = left$(buf$, num)
        goto [processContent]
    end if

[firstInputSkip]
    lf$ = chr$(10)

    cmdBuf$ = leftOver$ + left$(buf$, num)

[lineLoop]
    lineComplete = instr(cmdBuf$, crlf$)
    if lineComplete = 0 then
        lineComplete = instr(cmdBuf$, lf$)
        if lineComplete = 0 then
            leftOver$ = cmdBuf$
            goto [bufLoop]
        end if
        CR = 0
    else
        CR = 1
    end if

    cmd$ = trim$(left$(cmdBuf$, lineComplete - 1))

    Print "< ";cmd$;" - ";len(cmd$)

    if instr(cmd$, "Content-Length:") then
        ContentLength = val(word$(cmd$, 2))
        print "Content length found - ";ContentLength;" bytes"
    end if

    if cmd$ <> "" then

        cmdBuf$ = right$(cmdBuf$, len(cmdBuf$) - lineComplete - CR)
        goto [lineLoop]
    else
        cmdBuf$ = right$(cmdBuf$, len(cmdBuf$) - lineComplete - CR)
        Print "Headers complete, receiving content"
        open "output.html" for output as #outfile
        HeadersComplete = 1

        buf$ = cmdBuf$
    end if

[processContent]
    if len(buf$) = 0 then
        goto [bufLoop]
    end if

    bytes = len(buf$)
    totalBytesReceived = totalBytesReceived + bytes
    print "Received ";bytes;" bytes - ";totalBytesReceived;" out of ";ContentLength;" bytes"
    print #outfile, buf$;
    buf$ = ""

    if totalBytesReceived < ContentLength then goto [bufLoop]

[contentComplete]
    close #outfile

    a = DestroyTLSContext(hTLS)

[doSockEnd]
    a = CloseSocket(hServSock)

[doEnd]
    call CloseTLSDLL

Function randNum(min, max)
    randNum = int(rnd(1) * max) + min
End Function



'====================
'==Helper Functions==
'====================
Sub OpenTLSDLL
    open "Debug\LB-Schannel-Wrapper.dll" for DLL as #LBSchannelWrapper
    a = InitSockets()
End Sub

Sub CloseTLSDLL
    a = EndSockets()
    close #LBSchannelWrapper
End Sub

Function InitSockets()
    CallDLL #LBSchannelWrapper, "InitSockets",_
    InitSockets as long
End Function

Function EndSockets()
    CallDLL #LBSchannelWrapper, "EndSockets",_
    EndSockets as long
End Function

Function CreateTLSContext()
    CallDLL #LBSchannelWrapper, "CreateTLSContext",_
    CreateTLSContext as ulong
End Function

Function DestroyTLSContext(hTLS)
    CallDLL #LBSchannelWrapper, "DestroyTLSContext",_
    hTLS as ulong,_
    DestroyTLSContext as long
End Function

Function BeginTLSClientNoValidation(hTLS)
    CallDLL #LBSchannelWrapper, "BeginTLSClientNoValidation",_
    hTLS as ulong,_
    BeginTLSClientNoValidation as long
End Function

Function BeginTLSClient(hTLS)
    CallDLL #LBSchannelWrapper, "BeginTLSClient",_
    hTLS as ulong,_
    BeginTLSClient as long
End Function

Function IsSocketInvalid(sock)
    CallDLL #LBSchannelWrapper, "IsSocketInvalid",_
    sock as ulong,_
    IsSocketInvalid as long
End Function

Function BeginTLSServer(hTLS, serverName$)
    CallDLL #LBSchannelWrapper, "BeginTLSServer",_
    hTLS as ulong,_
    serverName$ as ptr,_
    BeginTLSServer as long
End Function

Function SetTLSSocket(hTLS, sock)
    CallDLL #LBSchannelWrapper, "SetTLSSocket",_
    hTLS as ulong,_
    sock as long,_
    SetTLSSock as long
End Function

Function PerformClientHandshake(hTLS, serverName$)
    CallDLL #LBSchannelWrapper, "PerformClientHandshake",_
    hTLS as ulong,_
    serverName$ as ptr,_
    PerformClientHandshake as long
End Function

Function PerformServerHandshake(hTLS, doInitialRead, initBuf$, initBufSize)
    CallDLL #LBSchannelWrapper, "PerformServerHandshake",_
    hTLS as ulong,_
    doInitialRead as long,_
    initBuf$ as ptr,_
    initBufSize as long,_
    PerformServerHandshake as long
End Function

Function CreateListenSocket(pService$)
    CallDLL #LBSchannelWrapper, "CreateListenSocket",_
    pService$ as ptr,_
    CreateListenSocket as ulong
End Function

Function AcceptConnection(ServerSocket)
    CallDLL #LBSchannelWrapper, "AcceptConnection",_
    ServerSocket as ulong,_
    AcceptConnection as ulong
End Function

Function IsReadAvailable(socket, msTimeout)
    CallDLL #LBSchannelWrapper, "IsReadAvailable",_
    socket as ulong,_
    msTimeout as long,_
    IsReadAvailable as long
End Function

Function IsTLSReadAvailable(hTLS, msTimeout)
    CallDLL #LBSchannelWrapper, "IsTLSReadAvailable",_
    hTLS as ulong,_
    msTimeout as long,_
    IsTLSReadAvailable as long
End Function

Function PingHost(host$, packetSize, byref status, byref msResponse, msTimeout)
    struct a, b as long
    struct c, d as long

    a.b.struct = status
    c.d.struct = msResponse

    CallDLL #LBSchannelWrapper, "PingHost",_
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
    CallDLL #LBSchannelWrapper, "Connect",_
    host$ as ptr,_
    srv$ as ptr,_
    msTimeout as long,_
    Connect as long
End Function

Function CloseSocket(sock)
    CallDLL #LBSchannelWrapper, "CloseSocket",_
    sock as long,_
    CloseSocket as long
End Function

Function GetError()
    CallDLL #LBSchannelWrapper, "GetError",_
    GetError as long

    if GetError < 0 then
        GetError = (abs(GetError) XOR hexdec("FFFFFFFF")) + 1
    end if
End Function

Function Send(sock, msg$, msgLen)
    CallDLL #LBSchannelWrapper, "Send",_
    sock as long,_
    msg$ as ptr,_
    msgLen as long,_
    Send as long
End Function

Function EncryptSend(hTLS, msg$, msgLen)
    CallDLL #LBSchannelWrapper, "EncryptSend",_
    hTLS as ulong,_
    msg$ as ptr,_
    msgLen as long,_
    EncryptSend as long
End Function

Function Receive(sock, byref buf$, bufLen)
    CallDLL #LBSchannelWrapper, "Receive",_
    sock as long,_
    buf$ as ptr,_
    bufLen as long,_
    Receive as long
End Function

Function DecryptReceive(hTLS, byref buf$, bufLen)
    CallDLL #LBSchannelWrapper, "DecryptReceive",_
    hTLS as ulong,_
    buf$ as ptr,_
    bufLen as long,_
    DecryptReceive as long
End Function

Function EndTLSClientSession(hTLS)
    CallDLL #LBSchannelWrapper, "EndTLSClientSession",_
    hTLS as ulong,_
    EndTLSClientSession as long
End Function


