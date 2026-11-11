import json, os, pwd, socket, struct, sys, time
work = sys.argv[1]
uid = pwd.getpwnam('nobody').pw_uid
runtime = work+'/runtime/'+str(uid)
def wait(predicate, description, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate(): return
        time.sleep(.03)
    raise AssertionError(description)
def rows():
    try:
        with open(work + '/apps.log') as stream: return [line.split() for line in stream if line.strip()]
    except FileNotFoundError: return []
def count(role, seat): return sum(row[0] == role and row[5] == seat for row in rows())
wait(lambda: count('greeter', 'seat-test') >= 1 and count('greeter', 'seat-other') >= 1, 'independent greeters did not launch')
initial_greeter = next(row for row in rows() if row[0] == 'greeter' and row[5] == 'seat-test')
peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); peer.settimeout(20); peer.connect(work + '/seat-test/greetd-seat-test-vt0.sock')
def exact(length):
    result = b''
    while len(result) < length:
        data = peer.recv(length-len(result))
        assert data, 'unexpected greetd EOF'
        result += data
    return result
def request(value):
    data = json.dumps(value).encode(); peer.sendall(struct.pack('=I', len(data)) + data)
    length = struct.unpack('=I', exact(4))[0]; assert length <= 65536
    return json.loads(exact(length))
def authenticate(password):
    reply = request({'type':'create_session','username':'fixture-name-not-a-real-account'})
    assert reply['type'] == 'auth_message', reply
    assert reply['auth_message_type'] == 'secret', reply
    return request({'type':'post_auth_message_response','response':password})
assert authenticate('wrong')['type'] == 'error'
assert authenticate('fixture-password')['type'] == 'success'
# A user-owned entrypoint receives authority like the greeter compositor;
# there is no wrapper recognition or trusted-executable allowlist.
launch = [work+'/with-seat'] if os.environ.get('GREETD_NATIVE') == '0' else []
reply = request({'type':'start_session', 'cmd':[work+'/user-entrypoint']+launch+[work+'/seat-client','user',work+'/apps.log',work+'/fixtures/seat-test/direct'],
                 'env':['XDG_SEAT=seat-spoofed','XDG_VTNR=63','XDG_RUNTIME_DIR=/bad','LD_PRELOAD=/bad.so','DBUS_SYSTEM_BUS_ADDRESS=unix:path=/bad','MULTISEATD_AUTHORITY_FD=2','WLR_BACKENDS=headless']})
assert reply['type'] == 'success', reply
peer.close()
wait(lambda: count('user','seat-test') >= 1, 'authenticated managed user did not launch')
# The old privileged host is deliberately inside its two-second PAM close.
# Positive device proof, NOT full worker exit, authorized this normal Start.
os.kill(int(initial_greeter[2]), 0)
with open(work+'/pam.log') as stream: overlap = [line.split() for line in stream]
assert any(row[0] == 'close-enter' and row[1] == initial_greeter[2] for row in overlap), overlap
assert not any(row[0] == 'close' and row[1] == initial_greeter[2] for row in overlap), 'handoff waited for final PAM/worker exit'
wait(lambda: count('greeter','seat-test') >= 2, 'logout did not launch a fresh greeter')
assert count('greeter','seat-other') == 1, 'unrelated seat was restarted'
entries = rows()
for row in entries:
    assert row[1] == row[3], ('compositor is not its own detached session leader', row)
    assert row[4] == str(os.stat(runtime).st_uid), row
    assert row[6] == runtime, row
with open(work+'/pam.log') as stream: pam = [line.split() for line in stream]
opened = [line for line in pam if line[0] == 'open']
assert len({line[1] for line in opened}) == len(opened), 'PAM opened twice in a worker'
assert all(line[2] == '0' and line[3] == 'nobody' and line[5] == '1' and line[6:] == ['-', '-'] for line in opened), opened
auth = [line for line in pam if line[0] == 'auth']
assert auth and all(line[4] == 'seat-test' and line[6:] == ['-', '-'] for line in auth), auth
assert all(row[2] in {line[1] for line in opened} for row in entries), (entries, opened)
print('Verified pre-auth metadata, final UID, detached workers, positive pre-PAM-close handoff and independent-seat logout passed')
