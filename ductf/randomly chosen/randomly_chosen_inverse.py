import random

output = open('ductf/randomly chosen/output.txt', 'r').read().strip()
len_flag = len(output) // 5
print(len_flag)
print(''.join(sorted(set(output))))


for seed in range(1337):
    random.seed(seed)
    flag = 'DUCTF{' + '.' * (len_flag - 7) + '}'

    out = ''.join(random.choices(flag, k=len(flag)*5))
    if all([
        out[i] == output[i] or out[i] == '.'
        for i in range(len(output))
    ]):
        print(seed)
        break

flag = list(range(61))
random.seed(seed)
transformation = random.choices(flag, k=len(flag)*5)

real_flag = ['.'] * len_flag
for i, c in zip(transformation, output):
    real_flag[i] = c

print(''.join(real_flag))