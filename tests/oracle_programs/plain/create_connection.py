import socket, sys
socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=2)
