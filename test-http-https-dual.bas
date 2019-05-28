    call OpenTLSDLL

    input "press ENTER to begin.";a

    hHTTPS = CreateListenSocket("443")
    if IsSocketInvalid(hHTTPS) then
        print "CreateListenSocket(443) failed. - ";GetError()
        goto [doEnd]
    end if

    print "CreateListenSocket(443) successful."

    hHTTP = CreateListenSocket("80")
    if IsSocketInvalid(hHTTP) then
        print "CreateListenSocket(80) failed. - ";GetError()
        a = CloseSocket(hHTTPS)
        goto [doEnd]
    end if

[awaitLoopStart]
    print "Checking if connection is available..."

[awaitLoop]
    timer 0

    ret = IsReadAvailable(hHTTP, 0)
    if ret > 0 then
        hServSock = hHTTP
        TLSActive = 0
        goto [acceptConnection]
    end if

    if ret = -1 then
        print "Error with IsReadAvailable(). - ";GetError()
        goto [doSockEnd]
    end if

    ret = IsReadAvailable(hHTTPS, 0)
    if ret > 0 then
        hServSock = hHTTPS
        TLSActive = 1
        goto [acceptConnection]
    end if

    if ret = -1 then
        print "Error with IsReadAvailable(). - ";GetError()
        goto [doSockEnd]
    end if

    timer 1, [awaitLoop]
    wait

[acceptConnection]
    Print "Attempting to accept connection..."
    hConn = AcceptConnection(hServSock)
    if hConn = -1 then
        print "AcceptConnection() failed. - ";GetError()
        goto [doSockEnd]
    end if

    if TLSActive = 0 then goto [bufLoopStart]

[beginTLS]

    print "Creating TLS context..."
    hTLS = CreateTLSContext()

    print "Acquiring TLS credentials..."
    fileName$ = "CA-test\localhost\localhost.pfx"
    ret = BeginTLSServerWithPFX(hTLS, "localhost", fileName$, "")
    if ret <> 0 then
        print "BeginTLSServer() failed. ret - ";ret;" -- Error - ";GetError()
        Print dechex$( (abs(ret) XOR hexdec("FFFFFFFF")) + 1)
        a = DestroyTLSContext(hTLS)
        goto [doSockEnd]
    end if

    Print "Finishing connection..."

[handshakeLoop]
    a = SetTLSSocket(hTLS, hConn)

    ret = PerformServerHandshake(hTLS, 1, "", 0)
    if ret <> 0 then
        print "PerformServerHandshake() failed. - ";ret; " - Error: ";dechex$(GetError())
        Print dechex$( (abs(ret) XOR hexdec("FFFFFFFF")) + 1)
        a = CloseSocket(hConn)
        a = DestroyTLSContext(hTLS)
        goto [doSockEnd]
    end if

[bufLoopStart]
    initTime = time$("seconds")
    print "Connection active, awaiting data..."

[bufLoop]
    timer 0
    if TLSActive then
        ret = IsTLSReadAvailable(hTLS, 0)
    else
        ret = IsReadAvailable(hConn, 0)
    end if

    if ret = 0 then
        'No data waiting.  Stop and wait.
        curTime = time$("seconds")
        if curTime > (initTime + 10) or curTime < initTime then
            print "Closing inactive connection."
            a = CloseSocket(hConn)

            if TLSActive then
                a = DestroyTLSContext(hTLS)
                hServSocket = 0
                hConn = 0
                TLSActive = 0
            end if
            goto [awaitLoopStart]
        end if
        timer 1, [bufLoop]
        wait
    end if

    bufLen = 512
    buf$ = space$(bufLen)
    if TLSActive then
        num = DecryptReceive(hTLS, buf$, bufLen)
    else
        num = Receive(hConn, buf$, bufLen)
    end if

    If num = -1 or (TLSActive = 0 AND num = 0) then
        Print "Socket error occurred. - ";GetError()
        a = CloseSocket(hConn)
        if TLSActive then
            a = DestroyTLSContext(hTLS)
        end if
        goto [awaitLoopStart]
    End if

[firstInputSkip]

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

    if instr(cmd$, "command=END") > 0 then
        ENDFLAG = 1
        print "END COMMAND RECEIVED, CLOSING SERVER."
    end if

    if word$(cmd$, 1) = "GET" then
        getPath$ = word$(cmd$, 2)
        if getPath$ <> "/" and left$(getPath$, 2) <> "/?" then
            doNotFound = 1
        else
            doNotFound = 0
        end if
    end if

    if cmdBuf$ <> crlf$ and cmdBuf$ <> lf$ then

        cmdBuf$ = right$(cmdBuf$, len(cmdBuf$) - lineComplete - CR)
        goto [lineLoop]
    end if

    if doNotFound then
        responseStatus$ = "HTTP/1.0 404 Not Found"
    else
        responseStatus$  = "HTTP/1.0 200 OK"
    end if

    responseHeaders$ = "Server: LB Test" + crlf$
    responseHeaders$ = responseHeaders$ + "Content-Language: en" + crlf$
    responseHeaders$ = responseHeaders$ + "Content-Type: text/html; charset=utf8" + crlf$
    responseHeaders$ = responseHeaders$ + "Connection: close" + crlf$

    if TLSActive then
        secure$ = "yes"
    else
        secure$ = "no"
    end if

    responseHeaders$ = responseHeaders$ + "X-Request-Secure: " + secure$ + crlf$

    if doNotFound then
        content$ = "404 File Not Found"
        lenContent = len(content$)
    else
        open "test.html" for input as #file
        content$ = input$(#file, lof(#file))
        close #file

        lenContent = len(content$)
    end if

    responseHeaders$ = responseHeaders$ + "Content-Length: " + str$(lenContent) + crlf$

    response$ = responseStatus$ + crlf$ + responseHeaders$ + crlf$ + content$

    lenResponse = len(response$)

    if TLSActive then
        ret = EncryptSend(hTLS, response$, lenResponse)
    else
        ret = Send(hConn, response$, lenResponse)
    end if
    print
    print response$

    a = CloseSocket(hConn)

    if TLSActive then
        a = DestroyTLSContext(hTLS)
    end if

    if ENDFLAG = 0 then
        hServSock = 0
        hConn = 0
        goto [awaitLoop]
    end if

[doSockEnd]
    a = CloseSocket(hHTTPS)
    a = CloseSocket(hHTTP)

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


