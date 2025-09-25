from Crypto.Util.number import long_to_bytes as l2b

with open('output.txt', 'r') as f:
    N = int(f.readline().split('=')[1].strip())
    e = int(f.readline().split('=')[1].strip())
    c = int(f.readline().split('=')[1].strip())

# factor of N
p = 71687846214813433073019418911783042175409794271603738798973474005704837225219
q = 113274254549741901861889819551932659355942317806815972293388207413147426065511

assert p*q == N, "Failed"

d = pow(e, -1, (p-1)*(q-1))
message = l2b(pow(c, d, N))

#print(message)

with open('decrypted.txt', 'wb') as f:
    f.write(message)