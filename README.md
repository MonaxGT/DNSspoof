DNS-spoofing detect tools
=======================

Run:
```
go run dnsspoof.go -f top-1000.txt -dsp 8.8.4.4 -dst 8.8.8.8 -d
```

Flags:
```
-f file with urls to check
-dsp possible spoofing server address (default:local)
-psp possible spoofing server port (default:53)
-dst trusted server (default:local)
-pst trusted server port (default:53)
-d debug mode with A-record value (default:false)
```

If spoofing dns-server return an empty record:
```
Alert: DNS spoof-server return an empty address badoo.com
```

If the spoof was detected:
```
----------------------------------------
Alert: address addthis.com not equal
Spoofing server: [208.49.103.220]
Standart server: [208.51.38.241]
-----------------------------------------
```
