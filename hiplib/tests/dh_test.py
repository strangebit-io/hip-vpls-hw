import sys
import os

from hiplib.utils import misc
from hiplib.crypto.dh import DH14
from binascii import hexlify

from diffiehellman import DiffieHellman

dh1 = DiffieHellman(group=14)
dh2 = DiffieHellman(group=14)

print(misc.Math.bytes_to_int(dh2.get_private_key()))

# get both public keys
dh1_public = dh1.get_public_key()
dh2_public = dh2.get_public_key()

# generate shared key based on the other side's public key
dh1_shared = dh1.generate_shared_key(dh2_public)
dh2_shared = dh2.generate_shared_key(dh1_public)

print(misc.Math.square_and_multiply(2, 8, 7))


print(hexlify(dh2_shared))
# the shared keys should be equal
assert dh1_shared == dh2_shared
dh = DH14()
dh.set_private_key(misc.Math.bytes_to_int(dh2.get_private_key()))
public = dh.generate_public_key()
print("---------")
print(hexlify(misc.Math.int_to_bytes(public)))
print(hexlify(dh2_public))
print("---------")
print(hexlify(misc.Math.int_to_bytes(dh.compute_shared_secret(misc.Math.bytes_to_int(dh1_public)))))

