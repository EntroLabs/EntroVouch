import socket as s, sys
k = s.socket()
k.settimeout(2)
k.connect(('127.0.0.1', int(sys.argv[1])))
