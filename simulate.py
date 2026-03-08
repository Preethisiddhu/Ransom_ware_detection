import os, time, random, string

sandbox = r'C:\Users\Admin\Desktop\test_sandbox'
os.makedirs(sandbox, exist_ok=True)

files = []
print('Creating 150 files...')
for i in range(150):
    p = os.path.join(sandbox, ''.join(random.choices(string.ascii_lowercase, k=8)) + '.docx')
    open(p, 'wb').write(os.urandom(4096))
    files.append(p)
    time.sleep(0.3)
    if i % 10 == 0:
        print(f'  created {i+1}/150')

print('Renaming to .locked...')
for p in files:
    try:
        os.rename(p, p + '.locked')
    except:
        pass
    time.sleep(0.3)

print('Deleting...')
for f in os.listdir(sandbox):
    try:
        os.remove(os.path.join(sandbox, f))
    except:
        pass
    time.sleep(0.2)

print('Simulation done!')