    open "Debug\LB-SChannel-Wrapper.dll" for DLL as #sc

    input "press ENTER to begin.";a

    message1$ = "GET /index.html HTTP/1.1"
    message2$ = "Host: chrisiverson.net"

'goto [skipTLS1]

    CallDLL #sc, "InitTLS",_
    hTLS as ulong

    Print hTLS

    CallDLL #sc, "BeginTLSClientNoValidation",_
    hTLS as ulong,_
    ret as long

    print "BeginTLS - ";ret

[skipTLS1]
'    hConn = TCPOpen("chrisiverson.net", 80)
'    hConn = TCPOpen("chrisiverson.net", 443)
'    print TCPPrint(hConn, message1$)
'    print TCPPrint(hConn, message2$)
'    print TCPPrint(hConn, "")
'    print TCPReceive$(hConn)

'    goto [skipTLS2]

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

    'res = TCPClose(hConn)

    close #sc
