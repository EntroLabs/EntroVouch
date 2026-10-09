"""Run one program with an audit hook installed and print what the hook saw.

usage: python _harness.py PROGRAM

The program is handed one argument: a loopback port that was closed a moment ago, so a connection
to it is refused and nothing leaves the machine.
"""
import json
import runpy
import socket
import sys

WATCHED = ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname", "socket.bind", "subprocess.Popen",
           "os.system", "os.exec", "os.posix_spawn", "os.startfile", "urllib.Request", "http.client.connect",
           "smtplib.connect", "ftplib.connect", "webbrowser.open")


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main() -> None:
    program = sys.argv[1]
    port = closed_port()
    seen = []
    on = [False]

    def hook(event, args):
        if on[0] and event.startswith(WATCHED):
            seen.append(event)

    sys.addaudithook(hook)
    sys.argv = [program, str(port)]
    on[0] = True
    try:
        runpy.run_path(program, run_name="__main__")
    except BaseException:
        pass
    on[0] = False
    print("EVENTS " + json.dumps(sorted(set(seen))))


if __name__ == "__main__":
    main()
