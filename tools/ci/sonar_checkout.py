"""Resolve one admitted GitHub revision and materialize its exact Git tree."""

from dataclasses import dataclass
from hashlib import sha1
import os
from pathlib import Path
import re

from sonar_exec import PublishError, capture


REPOSITORY = 'gorban/opencode-sandbox'
ORIGIN = f'https://github.com/{REPOSITORY}.git'
SHA = re.compile(r'[0-9a-f]{40}')
FILE_LIMIT = 2_000_000
TREE_LIMIT = 16_000_000
FETCH_LIMIT = 70_000_000


@dataclass(frozen=True)
class Revision:
    head: str
    base: str
    number: int | None = None
    branch: str = 'main'
    repository: str = REPOSITORY


def resolve(read_github, head, base, number=None):
    remote_main = read_github('git/ref/heads/main')['object']['sha']
    if base != remote_main:
        raise PublishError('The approved base is no longer the current upstream main')
    if number is None:
        if head != base:
            raise PublishError('Main approval must match the current upstream main')
        return Revision(head, base)
    pr = read_github(f'pulls/{number}')
    source, target = pr['head'], pr['base']
    if (pr['number'] != number or pr['state'] != 'open'
            or target['repo']['full_name'] != REPOSITORY or target['ref'] != 'main'
            or target['sha'] != base or source['sha'] != head or not source.get('repo')):
        raise PublishError('The open pull request does not match the approved head and base')
    branch = source['ref']
    if not re.fullmatch(r'[A-Za-z0-9_./+-]{1,240}', branch):
        raise PublishError('The pull request head branch name is unsupported')
    return Revision(head, base, number, branch, source['repo']['full_name'])


def git_env(home):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(home), 'XDG_CONFIG_HOME': str(home),
            'LANG': 'C', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_TERMINAL_PROMPT': '0'}


def git(cwd, env, *args, limit=1_000_000, timeout=30, monitor=None, bounded_file=False):
    prefix = ['/usr/bin/prlimit', '--fsize=64000000:64000000', '--'] if bounded_file else []
    command = prefix + ['/usr/bin/git', '--no-pager', '-c', 'core.hooksPath=/dev/null',
                        '-c', 'gc.auto=0', '-c', 'maintenance.auto=false', *args]
    code, out, _ = capture(command, cwd=cwd, env=env, limit=limit, timeout=timeout, monitor=monitor)
    if code:
        raise PublishError(f'Git {args[0]} failed (exit {code})')
    return out


def check_objects(repo):
    git_dir = repo / '.git'
    if any((git_dir / name).exists() for name in (
        'shallow', 'objects/info/alternates', 'objects/info/http-alternates', 'info/grafts', 'refs/replace',
    )):
        raise PublishError('Unexpected Git object configuration')


def checkout(root, revision):
    repo = root / 'source'
    repo.mkdir(mode=0o700)
    env = git_env(root / 'git-home')
    git(repo, env, 'init', '--quiet', '--template=', '--object-format=sha1')
    git(repo, env, 'remote', 'add', 'origin', ORIGIN)
    main_ref = 'refs/remotes/origin/main'
    head_ref = 'refs/sonar/head' if revision.number else main_ref
    refspecs = [f'refs/heads/main:{main_ref}']
    if revision.number:
        refspecs.append(f'refs/pull/{revision.number}/head:{head_ref}')
    git(repo, env, '-c', 'fetch.unpackLimit=1', '-c', 'fetch.fsckObjects=true', 'fetch', '--quiet', '--keep', '--no-tags',
        '--no-recurse-submodules', 'origin', *refspecs, timeout=150,
        monitor=lambda: check_fetch_size(repo / '.git'), bounded_file=True)
    check_objects(repo)
    for ref, expected in ((main_ref, revision.base), (head_ref, revision.head)):
        if git(repo, env, 'rev-parse', ref + '^{commit}').decode().strip() != expected:
            raise PublishError('Fetched revisions differ from the approved GitHub revisions')
    base = git(repo, env, 'merge-base', '--all', revision.base, revision.head).decode().splitlines()
    if len(base) != 1:
        raise PublishError('Expected a unique pull request merge base')
    git(repo, env, 'rev-list', '--objects', '--no-object-names', f'{base[0]}..{revision.head}', limit=500_000)
    main_commits = git(repo, env, 'rev-list', '--count', revision.base)
    head_commits = git(repo, env, 'rev-list', '--count', f'{base[0]}..{revision.head}')
    if int(main_commits) > 10_000 or int(head_commits) > 500:
        raise PublishError('Git history exceeds the publisher limit')
    materialize(repo, env, revision.head)
    git(repo, env, 'read-tree', revision.head)
    git(repo, env, 'update-ref', '--no-deref', 'HEAD', revision.head)
    return repo, env, base[0]


def check_fetch_size(directory):
    total = 0
    for path in directory.rglob('*'):
        try:
            if path.is_file():
                total += path.stat().st_size
        except FileNotFoundError:
            # Index-pack can rename a temporary file during the size check.
            continue
    if total > FETCH_LIMIT:
        raise PublishError('Git fetch exceeded the private storage limit')


def parse_tree(data):
    records = data.split(b'\0')[:-1]
    if not data.endswith(b'\0') or not 0 < len(records) <= 2000:
        raise PublishError('Git tree has an invalid file count')
    total = 0
    names = set()
    for record in records:
        attributes, name = record.split(b'\t', 1)
        mode, kind, oid, count = attributes.decode('ascii').split()
        parts = name.decode('utf-8').split('/')
        if (kind != 'blob' or mode not in ('100644', '100755') or not SHA.fullmatch(oid)
                or len(parts) > 16 or any(not re.fullmatch(r'[A-Za-z0-9_. @+()-]{1,120}', part)
                                        or part.lower() in ('.', '..', '.git') for part in parts)):
            raise PublishError('Git tree contains an unsupported file mode or path')
        size = int(count)
        total += size
        path = Path(*parts)
        if path in names or not 0 <= size <= FILE_LIMIT or total > TREE_LIMIT:
            raise PublishError('Git tree contains duplicate paths or exceeds size limits')
        names.add(path)
        yield path, oid, size, mode


def materialize(repo, env, revision):
    entries = tuple(parse_tree(git(repo, env, 'ls-tree', '-rlz', revision)))
    for path, oid, size, mode in entries:
        blob = git(repo, env, 'cat-file', 'blob', oid, limit=size + 2048)
        header = f'blob {size}\0'.encode('ascii')
        if len(blob) != size or sha1(header + blob, usedforsecurity=False).hexdigest() != oid:
            raise PublishError('Materialized Git blob differs from the tree')
        filename = repo / path
        filename.parent.mkdir(parents=True, exist_ok=True)
        with filename.open('xb') as stream:
            stream.write(blob)
        filename.chmod(0o755 if mode == '100755' else 0o644)


def changed_cores(repo, env, base, revision, cores):
    if revision.number is None:
        return set(cores)
    changed = git(repo, env, 'diff', '--no-ext-diff', '--no-renames', '--name-only', '-z',
                  base, revision.head, '--', *cores).decode('utf-8').split('\0')
    return set(cores).intersection(changed)
