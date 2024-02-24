import hashlib
import binascii


def hash_gen(a: int, b: int, c: int, k: int):
    ba = format(a, "#034b")[2: ]
    bb = format(b, "#034b")[2: ]
    bc = format(c, "#034b")[2: ]
    bk = format(k, "#034b")[2: ]
    
    bdata = ba + bb + bc + bk
    bdata_bytes = bytes.fromhex(bdata)
    hash = hashlib.sha256(bdata_bytes)
    hx = hash.hexdigest() # In Hex
    
    hh = bytearray(hash.digest()) # In Bytes
    i1 = hh[:16]
    i2 = hh[16:]
    val1 = int.from_bytes(i1,'big')
    val2 = int.from_bytes(i2,'big')
    
    return val1, val2

def zokIp(password: str, count: int):
    bin_pass = format(int(binascii.hexlify(bytes(password, "utf-8")), 16), "#098b")[2: ]
    a, b, c, k = int(bin_pass[: 32], 2), int(bin_pass[32: 64], 2), int(bin_pass[64: ], 2), count
    print(f"a: {a}\nb: {b}\nc: {c}\nk: {k}\n")
    v1, v2 = hash_gen(a, b, c, 0)
    print(f"sha256([a, b, c, 0]) =>\n  {v1}\n  {v2}\n")
    v1, v2 = hash_gen(a, b, c, k)
    print(f"sha256([a, b, c, k]) =>\n  {v1}\n  {v2}\n")
    
print("\nResults:\n")
zokIp("password", 1)