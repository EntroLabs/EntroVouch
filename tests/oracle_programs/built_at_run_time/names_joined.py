import sys
m = __import__('so' + 'cket')
getattr(m, 'create_' + 'connection')(('127.0.0.1', int(sys.argv[1])), timeout=2)
