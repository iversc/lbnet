    open "LB-Schannel-Wrapper\mesock32.dll" for DLL as #me
    open "Debug\LB-Schannel-Wrapper.dll" for DLL as #sc

    message$ = "GET /index.html http/1.1" + chr$(13) + chr$(10) + _
        "Host: chrisiverson.net"
    hConn = TCPOpen("chrisiverson.net", 443)
    CallDLL #sc, "InitTLS",_
    hConn as ulong,_
    hTLS as ulong

    CallDLL #sc, "BeginTLSClientNoValidation",_
    hTLS as ulong,_
    ret as long

    print "BeginTLS - ";ret

    CallDLL #sc, "PerformClientHandshake",_
    hTLS as ulong,_
    "chrisiverson.net" as ptr,_
    ret as long

    print "Handshake - ";ret

    CallDLL #sc, "EndTLS",_
    hTLS as ulong,_
    ret as void

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
