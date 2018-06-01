    call OpenTLSDLL

    input "press ENTER to begin.";a

    message1$ = "GET /index.html HTTP/1.1"
    message2$ = "Host: chrisiverson.net"

'goto [skipTLS1]

    CallDLL #LBSchannelWrapper, "InitTLS",_
    hTLS as ulong

    Print hTLS

    CallDLL #LBSchannelWrapper, "BeginTLSClientNoValidation",_
    hTLS as ulong,_
    ret as long

    print "BeginTLS - ";ret

[skipTLS1]
    'These two lines function identically.
    'You can specify known service ports(i.e. 80=http, 443=https, etc)
    'by their service name instead of port number.

    'sock = Connect("chrisiverson.net", "80", 0)
    sock = Connect("chrisiverson.net", "https", 0)

    If sock = -1 then
        print "Connect() failed. - ";
        print GetError()
        goto [end]
    end if

    message$ = message1$ + chr$(13) + chr$(10)
    message$ = message$ + message2$ + chr$(13) + chr$(10) + chr$(13) + chr$(10)
    lenMessage = len(message$)
    hConn = sock

goto [handshake]

    ret = Send(sock, message$, lenMessage)

    if ret < 0 then
        print "Send() failed. - ";
        print GetError()

        goto [socketEnd]
    end if

    bufLen = 1024
    buf$ = space$(bufLen)

    recCount = Receive(sock, buf$, bufLen)

    if recCount < 0 then
        print "Receive() failed - ";
        print GetError()
    end if

    print left$(buf$, recCount)

    goto [skipTLS2]
[handshake]

    CallDLL #LBSchannelWrapper, "SetTLSSocket",_
    hTLS as ulong,_
    hConn as ulong,_
    ret as long

    print "SetTLSSocket - ";ret

    CallDLL #LBSchannelWrapper, "PerformClientHandshake",_
    hTLS as ulong,_
    "chrisiverson.net" as ptr,_
    ret as long

    print "Handshake - ";ret

    CallDLL #LBSchannelWrapper, "EncryptSend",_
    hTLS as ulong,_
    message$ as ptr,_
    lenMessage as long,_
    ret as long

    If ret < 0 then
        Print "EncryptSend() failed. - ";GetError()
        goto [TLSend]
    End if

    Print "EncryptSend() succeeded."
    bufLen = 1024
    buf$ = space$(bufLen)

    CallDLL #LBSchannelWrapper, "DecryptReceive",_
    hTLS as ulong,_
    buf$ as ptr,_
    bufLen as long,_
    ret as long

    If ret < 0 then
        print "DecryptReceive() failed. - ";GetError()
        goto [TLSend]
    end if

    print "DecryptReceive() succeeded. - ";ret
    Print left$(buf$, ret)

    [TLSend]
    CallDLL #LBSchannelWrapper, "EndTLS",_
    hTLS as ulong,_
    ret as long

    [skipTLS2]

    'res = TCPClose(hConn)

    [socketEnd]
    ret = CloseSocket(sock)

    [end]
    call CloseTLSDLL

'====================
'==Helper Functions==
'====================
Sub OpenTLSDLL
    open "Debug\LB-Schannel-Wrapper.dll" for DLL as #LBSchannelWrapper
End Sub

Sub CloseTLSDLL
    close #LBSchannelWrapper
End Sub

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
