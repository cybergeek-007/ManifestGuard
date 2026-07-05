import httpx

base = 'http://127.0.0.1:8000/api'
results = []

# 1. Health
r = httpx.get(f'{base}/health')
results.append(('GET /health', r.status_code, str(r.json())))

# 2. List scans
r = httpx.get(f'{base}/scans')
scans = r.json()
results.append(('GET /scans', r.status_code, f'{len(scans)} scans'))

# 3. Single scan (Bitwarden)
r = httpx.post(f'{base}/scans/single', json={'extensionId': 'nngceckbapebfimnlniiiahkandclblb', 'enableAi': False}, timeout=60)
d = r.json()
sid = d.get('scanId') or d.get('scan_id')
results.append(('POST /scans/single (Bitwarden)', r.status_code, f'scanId={sid}'))

# 4. Get scan detail
r = httpx.get(f'{base}/scans/{sid}')
sd = r.json()
ext = sd['extensions'][0]
ename = ext.get('name', '?')
everdict = ext.get('verdict', '?')
results.append(('GET /scans/id', r.status_code, f'name={ename} verdict={everdict}'))

# 5. Get extension detail
eid = ext['id']
r = httpx.get(f'{base}/scans/{sid}/extensions/{eid}')
ed = r.json()
nsig = len(ed.get('suspiciousSignals', []))
nrec = len(ed.get('recommendations', []))
results.append(('GET /scans/id/ext/eid', r.status_code, f'signals={nsig} recs={nrec}'))

# 6. Reports
for fmt in ['csv', 'json', 'html', 'pdf']:
    r = httpx.get(f'{base}/scans/{sid}/reports/{fmt}')
    results.append((f'GET /reports/{fmt}', r.status_code, f'size={len(r.content)}'))

# 7. Invalid ID test
r = httpx.post(f'{base}/scans/single', json={'extensionId': 'INVALID', 'enableAi': False})
results.append(('POST /scans/single (INVALID)', r.status_code, 'Expected 400'))

# 8. Check removed endpoint
r = httpx.post(f'{base}/stats/uninstall', json={'extensionId': 'test', 'uninstalled': True})
results.append(('POST /stats/uninstall (REMOVED)', r.status_code, 'Expected 404/405'))

# 9. Chat (skip if no AI key)
r = httpx.post(f'{base}/scans/{sid}/extensions/{eid}/chat', json={'message': 'Is this safe?'}, timeout=30)
results.append(('POST /chat', r.status_code, f'reply_len={len(r.text)}'))

# 10. Recommendations
r = httpx.get(f'{base}/scans/{sid}/extensions/{eid}/recommendations')
results.append(('GET /recommendations', r.status_code, f'count={len(r.json()) if r.status_code == 200 else "N/A"}'))

print('=' * 70)
print('  FULL API ENDPOINT VERIFICATION')
print('=' * 70)
for name, status, detail in results:
    ok = status == 200 or (status >= 400 and ('INVALID' in name or 'REMOVED' in name))
    symbol = 'PASS' if ok else 'FAIL'
    print(f'  [{symbol}] {name}: {status} -> {detail}')
print('=' * 70)
