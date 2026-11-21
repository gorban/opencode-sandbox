"""Private rootless Podman environments for measuring and publishing coverage."""

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import tempfile

from sonar_coverage import REPORT_LIMIT
from sonar_exec import PublishError, capture
from sonar_state import owner_directory


PYTHON = 'docker.io/library/python@sha256:a61cbd76a882645de7f91423329fe43a67eed60d7da24f9e5331414bb3618b20'
SCANNER = 'docker.io/sonarsource/sonar-scanner-cli@sha256:6e6eca4d552695a98fb7dab84f0c1bd0885ebbfe272654d1552e24bd7f452d51'
PODMAN = '/usr/bin/podman'
SCAN_ENTRY = r'''
IFS= read -r token
status=0
SONAR_TOKEN="$token" /opt/sonar-scanner/bin/sonar-scanner "$@" >/scan/scan.log 2>&1 || status=$?
unset token
if ! grep -q 'Parsing .*coverage\.xml' /scan/scan.log; then
    if grep -qiE 'not authorized|401|403|authentication|token is invalid' /scan/scan.log; then exit 21; fi
    exit 22
fi
if [ "$status" = 0 ] && grep -qF 'QUALITY GATE STATUS: PASSED' /scan/scan.log; then
    gate=OK
elif [ "$status" != 0 ] && grep -qF 'QUALITY GATE STATUS: FAILED' /scan/scan.log; then
    gate=ERROR
else
    exit 23
fi
printf '%s\n' "$gate"
sed -n 's/^ceTaskId=//p' /scan/scanner/report-task.txt
'''


def podman_environment(root, runtime):
    for path in (root / 'home', root / 'graph', runtime / 'xdg', runtime / 'tmp', runtime / 'run'):
        path.mkdir(mode=0o700)
    conf = root / 'containers.conf'
    conf.write_text('[engine]\nlock_type="file"\ncgroup_manager="cgroupfs"\n', encoding='ascii')
    storage = root / 'storage.conf'
    storage.write_text(
        '[storage]\ndriver="vfs"\ngraphroot=' + json.dumps(str(root / 'graph'))
        + '\nrunroot=' + json.dumps(str(runtime / 'run')) + '\n', encoding='utf-8',
    )
    auth = root / 'auth.json'
    auth.write_text('{"auths":{}}\n', encoding='ascii')
    return {'PATH': '/usr/bin:/bin', 'HOME': str(root / 'home'), 'LANG': 'C',
            'XDG_CONFIG_HOME': str(root / 'home'), 'XDG_RUNTIME_DIR': str(runtime / 'xdg'),
            'TMPDIR': str(runtime / 'tmp'), 'CONTAINERS_CONF': str(conf),
            'CONTAINERS_STORAGE_CONF': str(storage), 'REGISTRY_AUTH_FILE': str(auth)}


class Store:
    def __init__(self, root, runtime):
        self.root = root
        self.runtime = runtime
        self.runtime_identity = owner_directory(runtime, private=True)
        self.env = podman_environment(root, runtime)
        self.identity = (root / 'graph').stat()
        self.flags = [PODMAN, '--root', str(root / 'graph'), '--runroot', str(runtime / 'run'),
                      '--tmpdir', str(runtime / 'tmp'), '--storage-driver=vfs', '--events-backend=file']

    def invoke(self, *args, **limits):
        return capture([*self.flags, *args], env=self.env, cwd=self.root, **limits)

    def require(self, *args, **limits):
        status, out, _ = self.invoke(*args, **limits)
        if status:
            raise PublishError(f'Private Podman {args[0]} failed (exit {status})')
        return out

    def verify(self):
        expected = f'{self.root}/graph|{self.runtime}/run|vfs|true'
        template = '{{.Store.GraphRoot}}|{{.Store.RunRoot}}|{{.Store.GraphDriverName}}|{{.Host.Security.Rootless}}'
        if self.require('info', '--format', template).decode().strip() != expected:
            raise PublishError('Podman did not select the expected private rootless store')

    def cleanup(self):
        if not os.path.samestat(self.identity, (self.root / 'graph').lstat()):
            raise PublishError('Private Podman store identity changed')
        if not os.path.samestat(self.runtime_identity, self.runtime.lstat()):
            raise PublishError('Private Podman runtime identity changed')
        self.require('rm', '--force', '--all', timeout=45)
        if self.require('ps', '--all', '--quiet').strip():
            raise PublishError('A container remains in the private Podman store')
        self.require('rmi', '--force', '--all', timeout=45)
        if self.require('images', '--quiet').strip():
            raise PublishError('An image remains in the private Podman store')
        self.require('unshare', '/usr/bin/rm', '-rf', '--', str(self.root / 'graph'), timeout=45)
        shutil.rmtree(self.runtime)
        shutil.rmtree(self.root)

    def run(self, image, args, entry, *, limit, timeout, payload=None):
        try:
            options = ['run', '--rm', '--pull=never', '--name=sonar-publisher', '--user=0',
                       '--pid=private', '--ipc=private', '--uts=private', '--cgroupns=private',
                       '--cap-drop=all', '--security-opt=no-new-privileges', '--log-driver=none',
                       '--no-healthcheck', '--image-volume=ignore', '--read-only', '--read-only-tmpfs=false',
                       '--ulimit=core=0:0', '--entrypoint=/bin/sh']
            if payload is not None:
                options.append('--interactive')
            return self.invoke(*options, *args, image, *entry, limit=limit, timeout=timeout, payload=payload)
        finally:
            # Also removes a container whose client timed out or whose pipe was closed.
            self.require('rm', '--force', '--ignore', 'sonar-publisher', timeout=45)
            if self.require('ps', '--all', '--quiet').strip():
                raise PublishError('Podman did not confirm that the container was removed')


@contextmanager
def private_store(root):
    root.mkdir(mode=0o700)
    session = Path(f'/run/user/{os.getuid()}')
    owner_directory(session, private=True)
    # pasta must open its namespace under the host session runtime directory.
    runtime = Path(tempfile.mkdtemp(prefix='oc-sonar-runtime-', dir=session))
    store = Store(root, runtime)
    store.verify()
    try:
        yield store
    finally:
        store.cleanup()


def mounts(source, inputs, scratch):
    return ['-v', f'{source}:/work:ro,Z', '-v', f'{inputs}:/inputs:ro,Z', '-w', '/work',
            f'--env=HOME={scratch}/home', f'--env=TMPDIR={scratch}']


def measure(store, source, tooling, wheel):
    store.require('pull', '--quiet', PYTHON, timeout=300)
    test_script = r'''
{
    mkdir /measure/home
    python -Im venv /measure/venv
    /measure/venv/bin/python -Im pip --isolated --disable-pip-version-check install \
        --no-index --no-deps --no-cache-dir --require-hashes -r /inputs/requirements.txt
    for suite do
        /measure/venv/bin/python -IB /inputs/measure.py run --append -m unittest discover -s tests --pattern="$suite"
    done
    kill -KILL -1 2>/dev/null || :
    /measure/venv/bin/python -IB /inputs/measure.py xml -o /measure/coverage.xml
} >/measure/measurement.log 2>&1
printf 'OC-COVERAGE-XML\n'
cat /measure/coverage.xml
'''
    options = ['--network=none', '--cpus=2', '--pids-limit=64', '--memory=512m',
               '--tmpfs=/measure:rw,exec,nosuid,nodev,size=192m,mode=0700',
               '--env=COVERAGE_RCFILE=/inputs/coverage.ini', '--env=COVERAGE_FILE=/measure/.coverage',
               *mounts(source, tooling, '/measure')]
    entry = ['-ec', test_script, 'measure', *wheel.CORES.values()]
    status, out, _ = store.run(PYTHON, options, entry, limit=REPORT_LIMIT, timeout=180)
    if status:
        raise PublishError(f'Coverage measurement failed (container exit {status})')
    return out


def scanner(store, source, inputs, properties, token):
    entry = ['-ec', 'mkdir /scan/home /scan/scanner-home\n' + SCAN_ENTRY,
             'scan', *('-D' + item for item in properties)]
    options = ['--network=pasta:--no-map-gw', '--cpus=4', '--pids-limit=200', '--memory=4g',
               '--tmpfs=/scan:rw,exec,nosuid,nodev,size=2g,mode=0700',
               '--env=JAVA_TOOL_OPTIONS=-XX:ActiveProcessorCount=4 -Djava.io.tmpdir=/scan',
               '--env=SONAR_USER_HOME=/scan/scanner-home', *mounts(source, inputs, '/scan')]
    status, output, _ = store.run(SCANNER, options, entry, limit=8192, timeout=480, payload=token + b'\n')
    if status:
        messages = {21: 'Sonar authentication or permission failed',
                    22: 'Scanner did not confirm parsing the coverage report',
                    23: 'Scanner did not confirm its task quality gate'}
        raise PublishError(messages.get(status, f'Scanner container failed (exit {status})'))
    return output.decode('ascii').splitlines()


def measurement_inputs(tooling, wheel_module, wheel_data):
    if sha256(wheel_data).hexdigest() != wheel_module.WHEEL_HASH:
        raise PublishError('Coverage.py wheel checksum mismatch')
    name = Path(wheel_module.WHEEL).name
    (tooling / name).write_bytes(wheel_data)
    (tooling / 'requirements.txt').write_text(
        f'/inputs/{name} --hash=sha256:{wheel_module.WHEEL_HASH}\n', encoding='ascii',
    )
    (tooling / 'measure.py').write_text(wheel_module.COVERAGE_ENTRY, encoding='ascii')
    config = '[run]\nbranch = true\nrelative_files = true\ninclude =\n    ' + '\n    '.join(wheel_module.CORES) + '\n'
    (tooling / 'coverage.ini').write_text(config, encoding='ascii')
