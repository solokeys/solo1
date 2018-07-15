from ecdsa import SigningKey, NIST256p

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


