import os, time, random, string

sandbox = r'C:\Users\Admin\Desktop\test_sandbox'
os.makedirs(sandbox, exist_ok=True)

# FIX: keep file handles open the entire time
handles = []
files = []

print('Creating 150 files...')
for i in range(150):
    p = os.path.join(sandbox, ''.join(random.choices(string.ascii_lowercase, k=8)) + '.locked')
    h = open(p, 'wb')
    h.write(os.urandom(4096))
    h.flush()
    handles.append(h)   # keep handle open — do NOT close yet
    files.append(p)
    time.sleep(0.1)
    if i % 10 == 0:
        print(f'  created {i+1}/150  ({len(handles)} files held open)')

print(f'\n{len(handles)} .locked files are now open — kill check should trigger NOW')
print('Sleeping 30 seconds so auto-kill has time to fire...')
time.sleep(30)   # server polls every 2s — plenty of time to detect and kill

print('Closing handles...')
for h in handles:
    try: h.close()
    except: pass

print('Simulation done!')