    open "LB-Schannel-Wrapper\mesock32.dll" for DLL as #me
    open "Debug\LB-SChannel-Wrapper.dll" for DLL as #sc

    input "press ENTER to begin.";a

    message1$ = "GET /index.html HTTP/1.1"
    message2$ = "Host: chrisiverson.net"

goto [skipTLS1]

    CallDLL #sc, "InitTLS",_
    hTLS as ulong

    Print hTLS

    CallDLL #sc, "BeginTLSClientNoValidation",_
    hTLS as ulong,_
    ret as long

    print "BeginTLS - ";ret

[skipTLS1]
    hConn = TCPOpen("chrisiverson.net", 80)
    print TCPPrint(hConn, message1$)
    print TCPPrint(hConn, message2$)
    print TCPPrint(hConn, "")
    print TCPReceive$(hConn)

    goto [skipTLS2]

    CallDLL #sc, "SetTLSSocket",_
    hTLS as ulong,_
    hConn as ulong,_
    ret as long

    print "SetTLSSocket - ";ret

    CallDLL #sc, "PerformClientHandshake",_
    hTLS as ulong,_
    "chrisiverson.net" as ptr,_
    ret as long

    print "Handshake - ";ret

    CallDLL #sc, "EndTLS",_
    hTLS as ulong,_
    ret as long

    [skipTLS2]

    res = TCPClose(hConn)

    close #sc
    close #me


    ''''Function TCPOpen()''''''''''
Function TCPOpen(address$,Port)
    Timeout=1000
    calldll #me, "Open", address$ As ptr,_
        Port As Long,_
        Timeout As Long, re As Long
    TCPOpen=re
End Function

''''Function TCPReceive$()''''''''''
Function TCPReceive$(handle)
    buffer=4096
    all=0
    calldll #me, "ReceiveA" ,handle As Long,_
        buffer As Long,_
        all As Long, re As long
    if re<>0 then TCPReceive$ = winstring(re)
End Function

''''Function TCPPrint()''''''''''
Function TCPPrint(handle,text$)
    calldll #me, "PrintA", handle As Long,_
        text$ As ptr,re As Long
    TCPPrint=re
End Function

''''Function TCPSend()''''''''''
Function TCPSend(handle,text$)
    calldll #me, "SendA", handle As Long,_
        text$ As ptr,re As Long
    TCPPrint=re
End Function

''''Function TCPClose()''''''''''
Function TCPClose(handle)
    calldll #me, "CloseA",handle As Long,_
        TCPClose As Long
End Function
