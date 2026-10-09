import socket, sys
s = socket.socket()
s.settimeout(2)
s.connect(('127.0.0.1', int(sys.argv[1])))
