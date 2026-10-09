import http.client, sys
c = http.client.HTTPConnection('127.0.0.1', int(sys.argv[1]), timeout=2)
c.request('GET', '/')
