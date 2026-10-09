import sys
from urllib.request import urlopen as fetch
fetch('http://127.0.0.1:%s/' % sys.argv[1], timeout=2)
