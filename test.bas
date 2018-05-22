open "LB-Schannel-Wrapper.dll" for DLL as #sc

struct a, pCredHandle as ulong

a.pCredHandle.struct = 0

callDLL #sc, "AcquireSChannelUnvalidatedCredHandle",_
a as struct,_
ret as ulong

print ret

pCredHandle = a.pCredHandle.struct
print pCredHandle

CallDLL #sc, "GetMaxMessageSize",_
bufSize as long

messageBuf$ = space$(bufSize)

struct b, phContext as ulong

CallDLL #sc, "InitSecurityContext",_
pCredHandle as ulong,_
0 as ulong,_
"chrisiverson.net" as ptr,_
0 as ulong,_
0 as long,_
b as struct,_
messageBuf$ as ptr,_
bufSize as long,_
ret as long

print "InitSecContext - ";ret
print messageBuf$

phContext = b.phContext.struct

CallDLL #sc, "DeleteSecContext",_
phContext as ulong,_
ret as long

print "DeleteSecContext - ";ret

    CallDLL #sc, "FreeCredHandle",_
    pCredHandle as ulong,_
    ret as long

    print ret
close #sc
