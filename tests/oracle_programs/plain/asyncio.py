import asyncio, sys
asyncio.run(asyncio.wait_for(asyncio.open_connection('127.0.0.1', int(sys.argv[1])), 2))
