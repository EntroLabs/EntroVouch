import hashlib, json
print(hashlib.sha3_256(json.dumps({'a': 1}).encode()).hexdigest())
