# Hosted-only verification/extraction. Never execute an unverified archive.
import hashlib,io,json,os,pathlib,tarfile,urllib.request
pins=json.load(open('release/controller-tools.json'))
assert pins['schema']=='a2a-controller-tools/1'
p=pins['actionlint']
assert p['version']=='1.7.7' and p['commit']=='03d0035246f3e81f36aed592ffb4bebf33a03106'
checks=urllib.request.urlopen(p['checksums_url']).read()
assert hashlib.sha256(checks).hexdigest()==p['checksums_sha256']
name=p['url'].rsplit('/',1)[1]
assert sum(line.split()[-1]==name and line.split()[0]==p['sha256'] for line in checks.decode().splitlines())==1
raw=urllib.request.urlopen(p['url']).read()
assert hashlib.sha256(raw).hexdigest()==p['sha256']
with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
    member=tf.getmember('actionlint');assert member.isfile()
    exe=tf.extractfile(member).read()
assert hashlib.sha256(exe).hexdigest()==p['executable_sha256']
out=pathlib.Path(os.environ['RUNNER_TEMP'])/'controller-tools'
out.mkdir(exist_ok=True)
(out/'actionlint').write_bytes(exe)
(out/'actionlint').chmod(0o755)
