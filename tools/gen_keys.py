from ecdsa import SigningKey, NIST256p
from ecdsa.util import randrange_from_seed__trytryagain
import sys

if len(sys.argv) > 1:
    print('using input seed file ', sys.argv[1])
    rng = open(sys.argv[1],'rb').read()
    secexp = randrange_from_seed__trytryagain(rng, NIST256p.order)
    sk = SigningKey.from_secret_exponent(secexp,curve = NIST256p)
else:
    sk = SigningKey.generate(curve = NIST256p)



sk_name = 'signing_key.pem'
print('Signing key for signing device firmware: '+sk_name)
open(sk_name,'wb+').write(sk.to_pem())

vk = sk.get_verifying_key()

print('Public key in various formats:')
print()
print([c for c in vk.to_string()])
print()
print(''.join(['%02x'%c for c in vk.to_string()]))
print()
print('"\\x' + '\\x'.join(['%02x'%c for c in vk.to_string()]) + '"')
print()


