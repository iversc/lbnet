
    call OpenTLSDLL

    input "press ENTER to begin.";a

    hServSock = CreateListenSocket("27016")
    if IsSocketInvalid(hServSock) then
        print "CreateListenSocket() failed. - ";GetError()
        goto [doEnd]
    end if

    print "CreateListenSocket() successful."

[awaitLoop]
    timer 0
    print "Checking if connection is available..."
    ret = IsReadAvailable(hServSock, 0)
    if ret = 0 then
        print "No connections yet.  Waiting..."
        timer 1, [awaitLoop]
        wait
    end if

    if ret = -1 then
        print "Error with IsReadAvailable(). - ";GetError()
        goto [doSockEnd]
    end if

    Print "Attempting to accept connection..."
    hConn = AcceptConnection(hServSock)
    if hConn = -1 then
        print "AcceptConnection() failed. - ";GetError()
        goto [doSockEnd]
    end if

    print "Creating TLS context..."
    hTLS = CreateTLSContext()

    print "Acquiring TLS credentials..."
    fileName$ = "CA-test\localhost\localhost.pfx"
    ret = BeginTLSServerWithPFX(hTLS, "localhost", fileName$, "")
    print "BeginTLSServerWithPFX return - ";ret
    if ret <> 0 then
        print "BeginTLSServer() failed. ret - ";ret;" -- Error - ";GetError()
        Print dechex$( (abs(ret) XOR hexdec("FFFFFFFF")) + 1)
        a = DestroyTLSContext(hTLS)
        goto [doSockEnd]
    end if

    Print "Finishing connection..."

[handshakeLoop]
    timer 0
    ret = IsReadAvailable(hConn, 0)
    if ret = 0 then
        'No data available this time.  Wait.
        timer 1, [handshakeLoop]
        wait
    end if

    if ret = -1 then
        Print "IsReadAvailable() failed. - ";GetError()
        a = CloseSocket(hConn)
        a = DestroyTLSContext(hTLS)
        goto [awaitLoop]
    end if

    a = SetTLSSocket(hTLS, hConn)

    ret = PerformServerHandshake(hTLS, 1, "", 0)
    if ret <> 0 then
        print "PerformServerHandshake() failed. - ";ret; " - Error: ";dechex$(GetError())
        a = CloseSocket(hConn)
        a = DestroyTLSContext(hTLS)
        goto [doSockEnd]
    end if

[bufLoop]
    timer 0
    ret = IsTLSReadAvailable(hTLS, 0)
    if ret = 0 then
        'No data waiting.  Stop and wait.
        timer 1, [bufLoop]
        wait
    end if

    bufLen = 512
    buf$ = space$(bufLen)
    num = DecryptReceive(hTLS, buf$, bufLen)
    If num = -1 then
        Print "Socket error occurred. - ";GetError()
        a = CloseSocket(hConn)
        a = DestroyTLSContext(hTLS)
        goto [awaitLoop]
    End if

    crlf$ = chr$(13) + chr$(10)
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

    Print "< ";cmd$

    if cmdBuf$ <> crlf$ and cmdBuf$ <> lf$ then

        cmdBuf$ = right$(cmdBuf$, len(cmdBuf$) - lineComplete - CR)
        goto [lineLoop]
    end if


    responseStatus$  = "HTTP/1.0 200 OK"
    responseHeaders$ = "Server: LB Test" + crlf$
    responseHeaders$ = responseHeaders$ + "Content-Language: en" + crlf$
    responseHeaders$ = responseHeaders$ + "Content-Type: text/html; charset=utf8" + crlf$
    responseHeaders$ = responseHeaders$ + "Connection: close" + crlf$

    open "test.html" for input as #file
    content$ = input$(#file, lof(#file))
    close #file

    lenContent = len(content$)

    responseHeaders$ = responseHeaders$ + "Content-Length: " + str$(lenContent) + crlf$

    response$ = responseStatus$ + crlf$ + responseHeaders$ + crlf$ + content$

    lenResponse = len(response$)

    ret = EncryptSend(hTLS, response$, lenResponse)
    print
    print response$

    a = CloseSocket(hConn)
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

Function BeginTLSServerWithPFX(hTLS, serverName$, certFileName$, certPass$)
    CallDLL #LBSchannelWrapper, "BeginTLSServerWithPFX",_
    hTLS as ulong,_
    serverName$ as ptr,_
    certFileName$ as ptr,_
    certPass$ as ptr,_
    BeginTLSServerWithPFX as long
End Function

Function SetTLSSocket(hTLS, sock)
    CallDLL #LBSchannelWrapper, "SetTLSSocket",_
    hTLS as ulong,_
    sock as long,_
    SetTLSSock as long
End Function

Function PerformClientHandshake(hTLS, servernName$)
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


