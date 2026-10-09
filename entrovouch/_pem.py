"""Private-key armour that holds a key.

A search string (`text.find(b"-----BEGIN EC PRIVATE KEY-----")`), an assertion on a line of output or a docstring
names the armour and holds no key. The armour holds one when a key body follows it, or when the text joins it to a
name the same file binds to a base64 literal (`b"-----BEGIN RSA PRIVATE KEY-----\\n" + B64PRIV_DER`).
"""
import re

# a key body: a long base64 run, or the start every DER key and OpenSSH key body has, followed by more base64
# (`MIIEow...`, `b3BlbnNzaC1rZXk...`); the OpenSSH start alone is a pattern a key detector names, not a key
_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}|(?:(?<![A-Za-z0-9+/])|(?<=\\n))(?:M[IHC][A-Za-z0-9+/]{2,}|b3BlbnNzaC1r[A-Za-z0-9+/]{4,})")
_JOINED = re.compile(r"\+\s*([A-Za-z_]\w*)")


def armour_with_key(text: str, armour: re.Pattern):
    """The first match of `armour` in `text` that holds a key, or None."""
    for m in armour.finditer(text):
        after = text[m.end():m.end() + 400]
        # the key is what stands before this armour's own END line: a certificate or a digest after a placeholder
        # (`<paste your key here>` then `-----END PRIVATE KEY-----`, then other text) is not this key's body
        end = after.find("-----END")
        if end >= 0:
            after = after[:end]
        if _BODY.search(after):
            return m
        for name in _JOINED.findall(after):
            bound = re.search(r"(?m)^[ \t]*" + re.escape(name) + r"[ \t]*=[ \t]*b?[\"']([A-Za-z0-9+/]{40,}={0,2})[\"']", text)
            if bound:
                return m
    return None
