import sys


def go():
    import socket
    socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=2)


go()
