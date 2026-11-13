#!/usr/bin/env python3
"""Private-bus/namespace integration. Arguments are explicit build artifacts."""
import json
import os
from pathlib import Path
import pwd
import shlex
import signal
import socket
import struct
import subprocess
import sys
import time

base, greetd, entry, native = map(Path, sys.argv[1:5])
address = os.environ['DBUS_SYSTEM_BUS_ADDRESS']
children = []

def wait_for(function, seconds=15):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            value = function()
            if value:
                return value
        except (OSError, ValueError, AssertionError, subprocess.CalledProcessError) as error:
            last = error
        time.sleep(.03)
    raise AssertionError(f'timed out: {function}, last={last}')

def contexts(seat='seat-test'):
    encoded = ''.join(c if c.isascii() and c.isalnum() else '_' + format(ord(c), '02x') for c in seat)
    result = subprocess.run([
        'busctl', '--address=' + address, '--json=short', 'call',
        'org.SGLogin.Multiseatd1.Seat_' + encoded,
        '/org/SGLogin/Multiseatd1', 'org.SGLogin.Multiseatd1.Manager', 'ListContexts',
    ], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)['data'][0]

def report_path(name):
    path = base / 'reports' / (name + '.json')
    path.write_text('')
    path.chmod(0o666)
    Path(str(path) + '.exit').unlink(missing_ok=True)
    return path

def report(path):
    return json.loads(path.read_text())

def command(path):
    return [shlex.join(['/usr/bin/python3', str(entry), str(path)])]

class Worker:
    def __init__(self, name, *, user='root', cls='User', **variables):
        self.name = name
        self.parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.parent.settimeout(15)
        self.extra = (base / 'unrelated-secret').open('rb')
        env = dict(os.environ, GREETD_TEST_LOG=str(base / (name + '.pam.log')), **variables)
        log = (base / (name + '.stderr')).open('wb')
        self.proc = subprocess.Popen([str(greetd), '--session-worker', str(child.fileno())],
                                     pass_fds=(child.fileno(), self.extra.fileno()), env=env,
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        children.append(self.proc)
        child.close()
        self.send({'InitiateLogin': {
            'service': 'seat-optional' if name == 'optional' else 'seat-test',
            'class': cls, 'user': user, 'authenticate': True,
            'tty': {'Multiseatd': {'config': {'seat': 'seat-test', 'vt': 0}, 'foreground': False}},
            'source_profile': False, 'listener_path': '/run/test-greeter.sock',
        }})
    def send(self, value):
        self.parent.send(json.dumps(value).encode())
    def recv(self):
        return json.loads(self.parent.recv(10240))
    def start(self, cmd):
        assert self.recv() == 'Success'
        self.send({'Args': {'env': ['XDG_SEAT=seat-wrong', 'XDG_VTNR=99',
                                   'MULTISEATD_AUTHORITY_FD=99'], 'cmd': cmd}})
        assert self.recv() == 'Success'
        self.send('Start')
        result = self.recv()
        assert 'FinalChildPid' in result, result
    def removed(self):
        result = self.recv()
        assert result == {'DeviceTeardown': {'Ok': None}}, result
    def finish(self):
        self.proc.wait(timeout=12)
        self.parent.close()
        self.extra.close()

try:
    wait_for(lambda: contexts() == [])
    # A missing runtime/session manager is not an extra greetd failure gate.
    for name, cls, variables in [
        ('greeter', 'Greeter', {}), ('user', 'User', {}),
        ('optional', 'User', {'GREETD_TEST_FAIL_OPEN': '1'}),
        ('close-failure', 'User', {'GREETD_TEST_FAIL_CLOSE': '1'}),
        ('final-user', 'User', {'GREETD_TEST_FINAL_USER': 'nobody'}),
    ]:
        path = report_path(name)
        gate = base / (name + '.close-gate')
        worker = Worker(name, cls=cls, GREETD_TEST_CLOSE_GATE=str(gate), **variables)
        worker.start(command(path))
        data = wait_for(lambda: report(path))
        env = data['env']
        expected_uid = pwd.getpwnam('nobody').pw_uid if name == 'final-user' else 0
        assert data['uid'] == expected_uid, data
        assert env['XDG_SEAT'] == 'seat-test' and 'XDG_VTNR' not in env, env
        assert env['LIBSEAT_BACKEND'] == 'multiseatd'
        authority = env['MULTISEATD_AUTHORITY_FD']
        assert data['fds'][authority].startswith('socket:'), data
        assert not any('unrelated-secret' in value for value in data['fds'].values()), data
        assert 'XDG_RUNTIME_DIR' not in env and 'XDG_SESSION_ID' not in env, env
        assert ('GREETD_SOCK' in env) == (cls == 'Greeter'), env
        rows = contexts()
        assert len(rows) == 1 and rows[0][1] == 0 and rows[0][2] == [expected_uid], rows
        assert rows[0][4:] == [True, False, True], rows
        acl = subprocess.check_output(['getfacl', '-cpn', str(base / 'fixture-a' / 'node')], text=True)
        assert f'user:{expected_uid}:rw-' in acl, acl
        Path(str(path) + '.exit').touch()
        worker.removed()
        assert contexts() == []
        assert worker.proc.poll() is None, 'device result did not precede held PAM close'
        gate.touch()
        if name == 'close-failure':
            assert 'Error' in worker.recv(), 'PAM close failure was hidden'
        worker.finish()
        log = (base / (name + '.pam.log')).read_text()
        assert 'auth\troot\t\tseat-test\t\n' in log, log
        assert 'close\t' in log and 'closed\t' in log, log
    print('PASS: greeter/user delegation, final PAM UID, optional PAM failure, actual ACL withdrawal before PAM close')

    worker = Worker('cancel')
    assert worker.recv() == 'Success'
    assert len(contexts()) == 1
    worker.send('Cancel')
    worker.removed()
    assert 'Error' in worker.recv()
    worker.finish()
    assert contexts() == []
    for name, variable, at_start in [
        ('auth-failure', 'GREETD_TEST_FAIL_AUTH', False),
        ('open-failure', 'GREETD_TEST_FAIL_OPEN', True),
    ]:
        worker = Worker(name, **{variable: '1'})
        if at_start:
            assert worker.recv() == 'Success'
            worker.send({'Args': {'env': [], 'cmd': ['true']}})
            assert worker.recv() == 'Success'
            worker.send('Start')
        worker.removed()
        assert 'Error' in worker.recv()
        worker.finish()
        assert contexts() == []
    worker = Worker('exec-failure')
    worker.start(['/nonexistent/greetd-test-command'])
    worker.removed()
    worker.finish()
    assert contexts() == []
    print('PASS: cancellation, required PAM failure and command exec failure remove their contexts')

    path = report_path('occupied')
    worker = Worker('occupied')
    worker.start(command(path))
    wait_for(lambda: report(path))
    old_id = contexts()[0][0]
    other = Worker('busy')
    assert other.recv() == 'Success'
    other.send({'Args': {'env': [], 'cmd': ['true']}})
    assert other.recv() == 'Success'
    other.send('Start')
    other.removed()
    assert 'Error' in other.recv()
    other.finish()
    assert [row[0] for row in contexts()] == [old_id]
    Path(str(path) + '.exit').touch()
    worker.removed()
    worker.finish()
    assert contexts() == []
    print('PASS: Busy never replaces the active context and failed Start removes only its own context')

    for cls in ['Greeter', 'User']:
        path = base / ('native-' + cls)
        worker = Worker('native-' + cls, cls=cls)
        worker.start([shlex.join([str(native), str(path)])])
        worker.removed()
        worker.finish()
        assert 'native authority consumed' in path.read_text()
        assert contexts() == []
    print('PASS: maintained C libseat consumes identically delegated greeter/user authority')

    # Exercise the real controller, PID sockets, marker files and checked handoff.
    controllers = []
    reports = []
    for index, seat in enumerate(['seat-test', 'seat-other']):
        path = report_path('controller-' + str(index))
        config = base / ('controller-' + str(index) + '.toml')
        runfile = base / ('started-' + str(index))
        config.write_text(f'''[general]
service = "seat-test"
source_profile = false
runfile = "{runfile}"
[multiseatd]
seat = "{seat}"
vt = "none"
[default_session]
command = {json.dumps(command(path)[0])}
user = "root"
service = "seat-test"
''')
        log = (base / ('controller-' + str(index) + '.stderr')).open('wb')
        proc = subprocess.Popen([str(greetd), '--config', str(config)], stdout=log, stderr=log,
                                stdin=subprocess.DEVNULL)
        children.append(proc)
        controllers.append(proc)
        data = wait_for(lambda: report(path))
        assert data['env']['XDG_SEAT'] == seat
        assert runfile.exists() and runfile.stat().st_size == 0
        assert Path(data['env']['GREETD_SOCK']).name == f'greetd-{proc.pid}.sock'
        reports.append((path, data))
    assert reports[0][1]['env']['GREETD_SOCK'] != reports[1][1]['env']['GREETD_SOCK']
    conn = socket.socket(socket.AF_UNIX)
    conn.settimeout(15)
    conn.connect(reports[0][1]['env']['GREETD_SOCK'])
    def request(value):
        payload = json.dumps(value).encode()
        conn.sendall(struct.pack('=I', len(payload)) + payload)
        def exact(length):
            result = b''
            while len(result) < length:
                more = conn.recv(length - len(result))
                assert more
                result += more
            return result
        return json.loads(exact(struct.unpack('=I', exact(4))[0]))
    greeter_id = contexts()[0][0]
    assert request({'type': 'create_session', 'username': 'root'})['type'] == 'success'
    assert len(contexts()) == 2
    assert request({'type': 'cancel_session'})['type'] == 'success'
    assert [row[0] for row in contexts()] == [greeter_id]
    assert request({'type': 'create_session', 'username': 'root'})['type'] == 'success'
    user_report = report_path('controller-user')
    assert request({'type': 'start_session', 'cmd': command(user_report), 'env': []})['type'] == 'success'
    Path(str(reports[0][0]) + '.exit').touch()
    wait_for(lambda: report(user_report))
    rows = contexts()
    assert len(rows) == 1 and rows[0][0] != greeter_id and rows[0][4] is True, rows
    user_id = rows[0][0]
    old_pid = reports[0][1]['pid']
    Path(str(reports[0][0]) + '.exit').unlink()
    Path(str(user_report) + '.exit').touch()
    wait_for(lambda: report(reports[0][0])['pid'] != old_pid)
    rows = contexts()
    assert len(rows) == 1 and rows[0][0] not in [greeter_id, user_id], rows
    assert len(contexts('seat-other')) == 1 and controllers[1].poll() is None
    conn.close()
    print('PASS: independent PID sockets/runfiles, cancellation, greeter->desktop->new-greeter handoff')

    # An actual worker crash is not equivalent to the positive teardown message.
    greeter = report(reports[0][0])
    status = Path(f'/proc/{greeter["pid"]}/status').read_text()
    host = int(next(line.split()[1] for line in status.splitlines() if line.startswith('PPid:')))
    assert b'--session-worker' in Path(f'/proc/{host}/cmdline').read_bytes()
    os.kill(host, signal.SIGKILL)
    assert controllers[0].wait(timeout=15) == 1
    wait_for(lambda: contexts() == [])
    assert 'without device-removal proof' in (base / 'controller-0.stderr').read_text()
    assert controllers[1].poll() is None
    print('PASS: actual PAM worker SIGKILL stops handoff without claiming teardown proof')

    def restart_controller(name):
        path = report_path('controller-0')
        log = (base / (name + '.stderr')).open('wb')
        proc = subprocess.Popen([str(greetd), '--config', str(base / 'controller-0.toml')],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        children.append(proc)
        wait_for(lambda: report(path))
        assert len(contexts()) == 1
        return proc, path

    # Stop only the explicit disposable daemon: a timed-out withdrawal is not a
    # successful handoff even if its work can complete after the daemon resumes.
    daemon = int(os.environ['GREETD_TEST_DAEMON_PID'])
    proc, path = restart_controller('timeout-controller')
    os.kill(daemon, signal.SIGSTOP)
    try:
        Path(str(path) + '.exit').touch()
        assert proc.wait(timeout=18) == 1
    finally:
        os.kill(daemon, signal.SIGCONT)
    wait_for(lambda: contexts() == [])
    assert 'device teardown is not complete' in (base / 'timeout-controller.stderr').read_text()
    print('PASS: actual SDK withdrawal timeout cannot authorize a normal successor')

    proc, path = restart_controller('owner-loss-controller')
    os.kill(daemon, signal.SIGTERM)
    time.sleep(.2)
    Path(str(path) + '.exit').touch()
    assert proc.wait(timeout=18) == 1
    assert 'device teardown is not complete' in (base / 'owner-loss-controller.stderr').read_text()
    assert len(contexts('seat-other')) == 1 and controllers[1].poll() is None
    print('PASS: actual daemon owner loss fails closed without controller RPC recovery')
finally:
    for child in reversed(children):
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
