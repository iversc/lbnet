    call OpenTLSDLL

    input "press ENTER to begin.";a

    hServSock = CreateListenSocket("27015")
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

    Print "Finishing connection..."

[bufLoop]
    timer 0
    ret = IsReadAvailable(hConn, 0)
    if ret = 0 then
        'No data available this time.  Wait.
        timer 1000, [bufLoop]
        wait
    end if

    if ret = -1 then
        Print "IsReadAvailable() failed. - ";GetError()
        a = CloseSocket(hConn)
        goto [awaitLoop]
    end if

    bufLen = 512
    buf$ = space$(bufLen)
    num = Receive(hConn, buf$, bufLen)
    If num = -1 then
        Print "Socket error occurred. - ";GetError()
        a = CloseSocket(hConn)
        goto [awaitLoop]
    End if

    If num = 0 then
        Print "Connection closed by remote host."
        a = CloseSocket(hConn)
        goto [awaitLoop]
    End If

    crlf$ = chr$(13) + chr$(10)

    cmdBuf$ = leftOver$ + left$(buf$, num)

[lineLoop]
    lineComplete = instr(cmdBuf$, crlf$)
    if lineComplete = 0 then
        leftOver$ = cmdBuf$
        goto [bufLoop]
    end if

    cmd$ = left$(cmdBuf$, lineComplete)
    Print "< ";cmd$

    if cmd$ = "END" then
        dataSend$ = "END RECEIVED, CLOSING CONNECTION." + chr$(13) + chr$(10)
    else
        dataSend$ = "DATA " + str$(randNum(1, 100)) + chr$(13) + chr$(10)
    end if

    print "> ";dataSend$
    sendLen = len(dataSend$)
    ret = Send(hConn, dataSend$, sendLen)
    if ret = -1 then
        print "Socket error occurred when sending data. - ";GetError()
        a = CloseSocket(hConn)
        goto [awaitLoop]
    end if

    if trim$(cmd$) = "END" then
        a = CloseSocket(hConn)
        cmdBuf$ = ""
        leftOver$ = ""
        goto [doSockEnd]
    end if

    cmdBuf$ = right$(cmdBuf$, len(cmdBuf$) - lineComplete - 2)
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

Function IsSocketInvalid(sock)
    CallDLL #LBSchannelWrapper, "IsSocketInvalid",_
    sock as ulong,_
    IsSocketInvalid as long
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

Function PingHost(host$, byref status, byref msResponse, msTimeout)
    struct a, b as long
    struct c, d as long

    a.b.struct = status
    c.d.struct = msResponse

    CallDLL #LBSchannelWrapper, "PingHost",_
    host$ as ptr,_
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

Function Receive(sock, byref buf$, bufLen)
    CallDLL #LBSchannelWrapper, "Receive",_
    sock as long,_
    buf$ as ptr,_
    bufLen as long,_
    Receive as long
End Function
