"""Owner-only main analysis attestation and a per-host publisher lock."""

from contextlib import contextmanager
import fcntl
import json
import os
import secrets
import stat

from sonar_exec import PublishError


def owner_directory(path, *, private=False):
    info = path.lstat()
    writable = 0o077 if private else 0o022
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & writable:
        raise PublishError('Expected an owner-controlled publisher directory')
    return info


@contextmanager
def state_directory(home):
    owner_directory(home)
    state = home / '.local' / 'state' / 'oc-sandbox' / 'sonar-publisher'
    for directory in reversed(state.parents):
        if directory.is_relative_to(home) and directory != home:
            directory.mkdir(mode=0o700, exist_ok=True)
            owner_directory(directory)
    state.mkdir(mode=0o700, exist_ok=True)
    expected = owner_directory(state, private=True)
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if not os.path.samestat(expected, os.fstat(fd)):
            raise PublishError('Publisher state directory changed while opening')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise PublishError('Another publisher is using the local state directory') from error
        yield state, fd
    finally:
        os.close(fd)


def check_directory(directory, fd):
    if not os.path.samestat(owner_directory(directory, private=True), os.fstat(fd)):
        raise PublishError('Publisher state directory changed')


def read_baseline(directory, fd):
    check_directory(directory, fd)
    try:
        handle = os.open('main.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError as error:
        raise PublishError('No trusted main receipt. Publish the current main revision first.') from error
    with os.fdopen(handle, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 32_768):
            raise PublishError('Unsafe or oversized main baseline receipt')
        data = stream.read(32_769)
        if len(data) != info.st_size:
            raise PublishError('Main baseline receipt changed during read')
        if not os.path.samestat(info, os.stat('main.json', dir_fd=fd, follow_symlinks=False)):
            raise PublishError('Main baseline receipt was replaced during read')
    check_directory(directory, fd)
    return json.loads(data)


def record_baseline(directory, fd, result):
    check_directory(directory, fd)
    name = '.pending-' + secrets.token_hex(12)
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(handle, 'w', encoding='ascii') as stream:
            json.dump(result, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        check_directory(directory, fd)
        os.replace(name, 'main.json', src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass
