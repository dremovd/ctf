import string

characters = open('ductf/flag art/output.txt', 'r').read().strip()
palette = {
    char: i
    for i, char in enumerate('.=w-o^*')
}
p_list = [2, 3, 5, 7]
characters = ''.join([c for c in characters if c in palette])
assert len(characters) % len(p_list) == 0

remainder_byte = {
    tuple(ord(c) % p for p in p_list): c 
    for c in string.ascii_letters + string.digits + '{}_?'
}

message_flag = []
for start in range(0, len(characters), len(p_list)):
    byte_chars = characters[start:start + len(p_list)]
    remainders = tuple(palette[c] for c in byte_chars)
    message_flag.append(remainder_byte.get(remainders, '^'))

print(''.join(message_flag))