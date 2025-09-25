from Crypto.Util.number import getPrime, bytes_to_long as b2l

with open('message.txt', 'rb') as f:
    message = f.read().strip()

p = getPrime(256)
q = getPrime(256)
N = p * q

assert b2l(message) < N

e = 65537
d = pow(e, -1, (p-1)*(q-1))
ciphertext = pow(b2l(message), e, N)

with open('output.txt', 'w') as f:
    f.write(f"N = {N}\n")
    f.write(f"e = {e}\n")
    f.write(f"c = {ciphertext}\n")