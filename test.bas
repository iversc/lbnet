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
        timer 1000, [awaitLoop]
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
    ret = BeginTLSServer(hTLS, "localhost")
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
        timer 1000, [handshakeLoop]
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
    ret = IsReadAvailable(hConn, 0)
    if ret = 0 then
        'No data waiting.  Stop and wait.
        timer 1000, [bufLoop]
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
    if cmd$ = "" then
        cmdBuf$ = right$(cmdBuf$, len(cmdBuf$) - lineComplete)
        goto [lineLoop]
    end if
    Print "< ";cmd$

    if cmd$ = "END" then
        dataSend$ = "END RECEIVED, TERMINATING SERVER." + chr$(13) + chr$(10)
    else
        if cmd$ = "CLOSE" then
            dataSend$ = "CLOSE RECEIVED, CLOSING CONNECTION AND ACCEPTING NEW ONE." + chr$(13) + chr$(10)
        else
            dataSend$ = "DATA " + str$(randNum(1, 100)) + chr$(13) + chr$(10)
        end if
    end if


    print "> ";dataSend$
    sendLen = len(dataSend$)
    ret = EncryptSend(hTLS, dataSend$, sendLen)
    if ret = -1 then
        print "Socket error occurred when sending data. - ";GetError()
        a = CloseSocket(hConn)
        a = DestroyTLSContext(hTLS)
        goto [awaitLoop]
    end if

    dataSend$ = ""

    if cmd$ = "END" or cmd$ = "CLOSE" then
        a = CloseSocket(hConn)
        a = DestroyTLSContext(hTLS)
        cmdBuf$ = ""
        leftOver$ = ""
        if cmd$ = "END" then [doSockEnd]
        goto [awaitLoop]
    end if

    cmdBuf$ = right$(cmdBuf$, len(cmdBuf$) - lineComplete - CR)
    goto [lineLoop]



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
    open "Debug\LBNet.dll" for DLL as #LBNet
    a = InitSockets()
End Sub

Sub CloseTLSDLL
    a = EndSockets()
    close #LBNet
End Sub

Function InitSockets()
    CallDLL #LBNet, "InitSockets",_
    InitSockets as long
End Function

Function EndSockets()
    CallDLL #LBNet, "EndSockets",_
    EndSockets as long
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


