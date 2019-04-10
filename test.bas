    call OpenTLSDLL

    input "press ENTER to begin.";a

    status = 0
    msResponse = 0

    a = PingHost("Chris-DF", status, msResponse, 1000)
    print "PingHost() - ";a
    if a = -1 then
        print "GetError() - ";GetError()
        print
    end if

    print "Status - ";status
    print "msResponse - ";msResponse



    call CloseTLSDLL

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
