import sys, urllib.request
urllib.request.urlopen('http://127.0.0.1:%s/' % sys.argv[1], timeout=2)
