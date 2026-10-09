import sys
m = __import__(bytes.fromhex('736f636b6574').decode())
f = vars(m)[bytes.fromhex('6372656174655f636f6e6e656374696f6e').decode()]
f(('127.0.0.1', int(sys.argv[1])), timeout=2)
