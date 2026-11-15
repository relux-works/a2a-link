# Verify immutable upstream archive and executable bytes before use.
import hashlib,json,os,pathlib,tarfile,urllib.request
pins=json.load(open('release/linux-tools.json'))
root=pathlib.Path(os.environ['RUNNER_TEMP'])/'tools'
for name in ['goreleaser','syft']:
    pin=pins[name]
    checksum_name='checksums.txt' if name=='goreleaser' else 'syft_'+pin['version'][1:]+'_checksums.txt'
    checksums=urllib.request.urlopen(pin['url'].rsplit('/',1)[0]+'/'+checksum_name).read()
    assert hashlib.sha256(checksums).hexdigest()==pin['checksums_sha256'], name+' upstream checksum-list pin'
    expected=pin['sha256']+'  '+pin['url'].rsplit('/',1)[1]
    assert checksums.decode().splitlines().count(expected)==1, name+' upstream archive association'
    data=urllib.request.urlopen(pin['url']).read()
    assert hashlib.sha256(data).hexdigest()==pin['sha256'], name+' archive pin'
    archive=root/(name+'.tar.gz');archive.write_bytes(data)
    with tarfile.open(archive) as tf:
        member=tf.getmember(name)
        assert member.isfile(), name+' executable type'
        binary=tf.extractfile(member).read()
    assert hashlib.sha256(binary).hexdigest()==pin['executable_sha256'], name+' executable pin'
    executable=root/name;executable.write_bytes(binary);executable.chmod(0o755)
