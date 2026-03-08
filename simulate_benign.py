import os, time, random, string

sandbox = r'C:\Users\Admin\Desktop\test_sandbox'
os.makedirs(sandbox, exist_ok=True)

def rname(ext):
    return ''.join(random.choices(string.ascii_lowercase, k=8)) + ext

exts = ['.txt', '.docx', '.pdf', '.xlsx', '.jpg', '.png']

print('Simulating normal file activity...')
files = []

for i in range(200):
    ext = random.choice(exts)
    p = os.path.join(sandbox, rname(ext))
    with open(p, 'w') as f:
        f.write('normal document content ' * 100)
    files.append(p)
    time.sleep(0.3)
    if i % 20 == 0:
        print(f'  created {i+1}/200')

print('Modifying files...')
for p in random.sample(files, 50):
    try:
        with open(p, 'a') as f:
            f.write('edited content\n')
    except:
        pass
    time.sleep(0.2)

print('Deleting some files...')
for p in random.sample(files, 30):
    try:
        os.remove(p)
    except:
        pass
    time.sleep(0.2)

print('Benign simulation done!')