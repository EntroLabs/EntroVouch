import subprocess, sys
subprocess.run([sys.executable, '-c', 'import socket; socket.getaddrinfo("localhost", 80)'])
