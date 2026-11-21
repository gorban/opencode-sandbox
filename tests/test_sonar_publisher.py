"""Test exact-revision admission and the publisher's untrusted boundaries."""

from datetime import datetime, timezone
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools' / 'ci'))

import sonar_checkout as checkout
import sonar_cloud as cloud
import sonar_coverage as coverage
from sonar_exec import PublishError, capture
import sonar_publish as publish
import sonar_sandbox as sandbox
import sonar_state as state


BASE = 'a' * 40
HEAD = 'b' * 40
TASK = 'AaH_hkQkkJctEnst8Jf9'
ANALYSIS = 'f963b3df-c976-45f9-aa0e-ef912e10f1a6'
SINCE = datetime(2026, 11, 21, 19, 12, 1, tzinfo=timezone.utc)
REVISION = checkout.Revision(HEAD, BASE, 36, 'fix/readme', 'fork/opencode-sandbox')
COUNTS = {'lines_to_cover': 1, 'uncovered_lines': 0, 'conditions_to_cover': 2, 'uncovered_conditions': 1}
PATH = 'core.py'


def github_pr():
    return {'number': 36, 'state': 'open',
            'head': {'repo': {'full_name': REVISION.repository}, 'ref': REVISION.branch, 'sha': HEAD},
            'base': {'repo': {'full_name': checkout.REPOSITORY}, 'ref': 'main', 'sha': BASE}}


def ce_task():
    return {'id': TASK, 'componentKey': cloud.PROJECT, 'pullRequest': '36', 'branch': None, 'status': 'SUCCESS',
            'analysisId': ANALYSIS, 'submittedAt': '2026-11-21T19:12:31+0000',
            'startedAt': '2026-11-21T19:12:32+0000', 'executedAt': '2026-11-21T19:12:33+0000'}


class CheckoutTest(unittest.TestCase):
    def test_fork_selection_and_rejects_stale_or_closed_pr(self):
        pr = github_pr()

        def read(endpoint):
            return {'object': {'sha': BASE}} if endpoint == 'git/ref/heads/main' else pr

        self.assertEqual(checkout.resolve(read, HEAD, BASE, 36), REVISION)
        with self.assertRaises(PublishError):
            checkout.resolve(read, HEAD, 'c' * 40, 36)
        pr['head']['sha'] = BASE
        with self.assertRaises(PublishError):
            checkout.resolve(read, HEAD, BASE, 36)
        pr.update(github_pr())
        pr['state'] = 'closed'
        with self.assertRaises(PublishError):
            checkout.resolve(read, HEAD, BASE, 36)

    def test_tree_rejects_links_submodules_and_unsafe_paths(self):
        for mode, kind, path in [
            ('120000', 'blob', 'link'), ('160000', 'commit', 'module'),
            ('100644', 'blob', 'a/.git/config'), ('100644', 'blob', 'a/../b'),
            ('100644', 'blob', 'control\nfile'), ('100644', 'blob', 'a' * 121),
        ]:
            with self.subTest(path=path, mode=mode), self.assertRaises(PublishError):
                list(checkout.parse_tree(f'{mode} {kind} {HEAD} 1\t{path}\0'.encode()))
        with self.assertRaises(PublishError):
            list(checkout.parse_tree(f'100644 blob {HEAD} 2000001\ttoo-large\0'.encode()))

    def test_materialization_uses_blob_bytes_even_with_git_eol_attributes(self):
        with TemporaryDirectory() as directory:
            repo = Path(directory)
            env = checkout.git_env(repo / 'no-home')

            def git(*args):
                return checkout.git(repo, env, *args)

            git('init', '--quiet', '--template=')
            (repo / '.gitattributes').write_text('example text eol=crlf\n', encoding='ascii')
            (repo / 'example').write_bytes(b'a\nb\n')
            git('add', '--', '.gitattributes', 'example')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                'commit', '--quiet', '-m', 'Set fixture attributes')
            (repo / '.gitattributes').unlink()
            (repo / 'example').unlink()
            checkout.materialize(repo, env, 'HEAD')
            self.assertEqual((repo / 'example').read_bytes(), b'a\nb\n')

    def test_rejects_git_object_indirection(self):
        with TemporaryDirectory() as directory:
            repo = Path(directory)
            (repo / '.git/objects/info').mkdir(parents=True)
            (repo / '.git/objects/info/alternates').touch()
            with self.assertRaises(PublishError):
                checkout.check_objects(repo)


class CoverageTest(unittest.TestCase):
    def setUp(self):
        scratch = TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.source = Path(scratch.name)
        (self.source / PATH).write_text('if check():\n    action()\n', encoding='ascii')
        self.body = (
            '<coverage><packages><package><classes><class filename="core.py">'
            '<lines><line number="1" hits="1" branch="true" condition-coverage="50% (1/2)"/>'
            '</lines></class></classes></package></packages></coverage>'
        )

    def decode(self, xml):
        return coverage.canonical_report(coverage.REPORT_HEADER + xml.encode(), self.source, [PATH])

    def test_rewrites_untrusted_metadata_and_counts(self):
        got = self.decode(self.body.replace('<coverage>', '<coverage ignored="anything">'))
        self.assertEqual(got.metrics, {PATH: COUNTS})
        self.assertNotIn(b'ignored=', got.xml)

    def test_rejects_entities_paths_inconsistent_counts_and_invalid_lines(self):
        for xml in (
            '<!DOCTYPE coverage [<!ENTITY use SYSTEM "file:///etc/passwd">]>' + self.body,
            self.body.replace(PATH, '../core.py'),
            self.body.replace('1/2', '3/2'),
            self.body.replace('number="1"', 'number="3"'),
            self.body.replace('number="1"', 'number="١"'),
            self.body.replace('1/2', '١/2'),
            self.body.replace('hits="1"', 'hits="0"'),
            self.body.replace('</line>', '')[:-1],
        ):
            with self.subTest(xml=xml), self.assertRaises(PublishError):
                self.decode(xml)

    def test_requires_bounded_framing(self):
        with self.assertRaises(PublishError):
            self.decode('x' * coverage.REPORT_LIMIT)
        unframed = self.body.encode()
        with self.assertRaises(PublishError):
            coverage.canonical_report(unframed, self.source, [PATH])


class CloudTest(unittest.TestCase):
    def test_exact_ce_task_context_and_timestamps(self):
        response = {'queue': [], 'current': ce_task()}
        with patch.object(cloud, 'sonar', return_value=response):
            self.assertEqual(cloud.task_snapshot(REVISION, TASK, SINCE)[0], ANALYSIS)
            for key, value in [('pullRequest', '37'), ('componentKey', 'other'),
                               ('submittedAt', '2026-11-21T19:10:00+0000'), ('id', 'another-task')]:
                with self.subTest(key=key), patch.dict(response['current'], {key: value}):
                    with self.assertRaises(PublishError):
                        cloud.task_snapshot(REVISION, TASK, SINCE)
            with patch.dict(response, {'queue': [{'id': 'another-task'}]}), self.assertRaises(PublishError):
                cloud.task_snapshot(REVISION, TASK, SINCE)

    def test_scope_verification_requires_expected_file_but_allows_unchanged_absence(self):
        absent = HTTPError('https://example.invalid', 404, 'missing', {}, None)
        with patch.object(cloud, 'sonar', side_effect=absent):
            self.assertEqual(cloud.verify_metrics(REVISION, {PATH: COUNTS}, set()), {})
            with self.assertRaises(HTTPError):
                cloud.verify_metrics(REVISION, {PATH: COUNTS}, {PATH})
        case = {'component': {'path': PATH, 'measures': [
            {'metric': k, 'value': str(v)} for k, v in COUNTS.items()
        ]}}
        with patch.object(cloud, 'sonar', return_value=case):
            self.assertEqual(cloud.verify_metrics(REVISION, {PATH: COUNTS}, {PATH}), {PATH: COUNTS})
            case['component']['measures'][0]['value'] = '0'
            with self.assertRaises(PublishError):
                cloud.verify_metrics(REVISION, {PATH: COUNTS}, {PATH})

    def test_main_error_is_distinct_from_coverage_waiver(self):
        gate = {'status': 'ERROR', 'conditions': []}
        main = checkout.Revision(BASE, BASE)
        with patch.object(cloud, 'sonar', return_value={'projectStatus': gate}):
            self.assertEqual(cloud.gate_for(main, ANALYSIS, 'ERROR'), gate)
            with self.assertRaises(PublishError):
                cloud.gate_for(REVISION, ANALYSIS, 'ERROR')

    def test_native_gate_red_and_green(self):
        condition = {'metricKey': 'new_coverage', 'status': 'ERROR', 'errorThreshold': '100',
                     'comparator': 'LT', 'actualValue': '96.6'}
        gate = {'status': 'ERROR', 'conditions': [condition], 'ignoredConditions': False}
        with patch.object(cloud, 'sonar', return_value={'projectStatus': gate}):
            self.assertEqual(cloud.gate_for(REVISION, ANALYSIS, 'ERROR'), gate)
            gate['status'] = 'OK'
            with self.assertRaises(PublishError):
                cloud.gate_for(REVISION, ANALYSIS, 'OK')
            condition.update(status='OK', actualValue='100.0')
            self.assertEqual(cloud.gate_for(REVISION, ANALYSIS, 'OK'), gate)
            gate['ignoredConditions'] = True
            with self.assertRaises(PublishError):
                cloud.gate_for(REVISION, ANALYSIS, 'OK')

    def test_fresh_exact_pr_native_check(self):
        response = {'total_count': 1, 'check_runs': [{
            'id': 1, 'name': 'SonarCloud Code Analysis', 'app': {'id': 12526},
            'head_sha': HEAD, 'status': 'completed', 'conclusion': 'success',
            'completed_at': '2026-11-21T19:12:33Z', 'html_url': 'expected',
            'details_url': f'https://sonarcloud.io/dashboard?id={cloud.PROJECT}&pullRequest=36',
        }]}
        with patch.object(cloud, 'github', return_value=response):
            self.assertEqual(cloud.wait_for_check(REVISION, 'OK', SINCE, 0), 'expected')
            check = response['check_runs'][0]
            with patch.dict(check, {'conclusion': 'neutral'}), self.assertRaises(PublishError):
                cloud.wait_for_check(REVISION, 'OK', SINCE, 0)
            for overrides in ({'completed_at': '2026-11-21T19:10:00Z'},
                              {'details_url': check['details_url'].replace('36', '37')},
                              {'head_sha': BASE}, {'app': {'id': 57789}}):
                with patch.dict(check, overrides), patch.object(cloud.time, 'monotonic', side_effect=(0, 1, 181)):
                    with patch.object(cloud.time, 'sleep'), self.assertRaises(PublishError):
                        cloud.wait_for_check(REVISION, 'OK', SINCE, 0)

    def test_preexisting_same_second_check_cannot_satisfy_freshness(self):
        existing = {'id': 15, 'name': 'SonarCloud Code Analysis', 'app': {'id': 12526},
                    'head_sha': HEAD, 'status': 'completed', 'conclusion': 'success',
                    'completed_at': '2026-11-21T19:12:01Z', 'html_url': 'old',
                    'details_url': f'https://sonarcloud.io/dashboard?id={cloud.PROJECT}&pullRequest=36'}
        response = {'total_count': 1, 'check_runs': [existing]}
        with patch.object(cloud, 'github', return_value=response):
            previous = cloud.native_check_id(REVISION)
            self.assertEqual(previous, 15)
            same_second = SINCE.replace(microsecond=500000)
            with patch.object(cloud.time, 'monotonic', side_effect=(0, 1, 181)):
                with patch.object(cloud.time, 'sleep'), self.assertRaises(PublishError):
                    cloud.wait_for_check(REVISION, 'OK', same_second, previous)
            response.update(total_count=2, check_runs=[existing, {**existing, 'id': 16, 'html_url': 'new'}])
            self.assertEqual(cloud.wait_for_check(REVISION, 'OK', SINCE, previous), 'new')

    def test_incomplete_native_check_inventory_is_rejected(self):
        with patch.object(cloud, 'github', return_value={'total_count': 101, 'check_runs': []}):
            with self.assertRaises(PublishError):
                cloud.native_check_id(REVISION)


class BootstrapTest(unittest.TestCase):
    def test_checkout_rejects_unlisted_git_operations_before_subprocess(self):
        root = Path.cwd()
        with patch.object(publish.subprocess, 'check_output') as run:
            with self.assertRaises(ValueError):
                publish.trusted_git(root, '--version')
            run.assert_not_called()

    def test_blob_reader_rejects_bad_revision_or_path_before_subprocess(self):
        root = Path.cwd()
        with patch.object(publish.subprocess, 'check_output') as run:
            for revision, path in [('--help', '.sonarcloud.properties'), (HEAD, 'AGENTS.md')]:
                with self.subTest(revision=revision, path=path), self.assertRaises(ValueError):
                    publish.publisher_blob(root, revision, path)
            run.assert_not_called()

    def test_blob_reader_only_reads_a_single_regular_inventory_entry(self):
        root = Path.cwd()
        path = '.sonarcloud.properties'
        record = f'100644 blob {BASE}\t{path}\0'.encode('ascii')
        with patch.object(publish.subprocess, 'check_output', side_effect=[record, b'reviewed']) as run:
            self.assertEqual(publish.publisher_blob(root, HEAD, path), b'reviewed')
            self.assertEqual(run.call_args_list[-1].args[0][-3:], ['cat-file', 'blob', BASE])
        for entries in [b'', record * 2, record.replace(b'100644', b'120000'),
                        record.replace(b'.sonarcloud.properties', b'other-file')]:
            with patch.object(publish.subprocess, 'check_output', return_value=entries) as run:
                with self.assertRaises(ValueError):
                    publish.publisher_blob(root, HEAD, path)
                run.assert_called_once()

    def test_caller_environment_is_cleared_before_network_boundary(self):
        options = SimpleNamespace(checkout=Path.cwd(), publisher=HEAD)
        ambient = {'HTTPS_PROXY': 'synthetic-proxy', 'SSL_CERT_FILE': 'synthetic-ca',
                   'SSLKEYLOGFILE': 'synthetic-log', 'SONAR_TOKEN': 'synthetic-token'}

        def enter_network_boundary(*args):
            self.assertFalse(os.environ)
            return 0

        with (patch.dict(os.environ, ambient, clear=True),
              patch.object(sys, 'argv', ['-']),
              patch.object(sys, 'flags', SimpleNamespace(isolated=True)),
              patch.object(os, 'umask'),
              patch.object(publish, 'require_host'),
              patch.object(publish.resource, 'setrlimit'),
              patch.object(publish.signal, 'signal'),
              patch.object(publish, 'parse_args', return_value=options),
              patch.object(publish, 'trusted_checkout'),
              patch.object(publish, 'run', side_effect=enter_network_boundary)):
            self.assertEqual(publish.main(), 0)


class SandboxTest(unittest.TestCase):
    def test_attached_stdout_and_stderr_share_output_bound(self):
        command = [sys.executable, '-c',
                   'import os; os.write(1, b"o" * 256); os.write(2, b"e" * 256)']
        with self.assertRaisesRegex(PublishError, 'output limit'):
            capture(command, cwd=Path.cwd(), env={}, limit=400)

    def test_container_removed_even_if_attached_output_fails(self):
        store = Mock(spec=sandbox.Store)
        store.invoke.side_effect = PublishError('output limit')
        store.require.return_value = b''
        with self.assertRaises(PublishError):
            sandbox.Store.run(store, 'image', ['--network=none'], ['-ec', 'unused'],
                              limit=8, timeout=1)
        store.require.assert_any_call('rm', '--force', '--ignore', 'sonar-publisher', timeout=45)
        store.require.assert_any_call('ps', '--all', '--quiet')

    def test_coverage_has_no_writable_host_mount_or_token(self):
        store = Mock()
        store.run.return_value = (0, coverage.REPORT_HEADER, b'')
        suite = 'test core.py'
        wheel = Mock(CORES={'core.py': suite})
        sandbox.measure(store, Path('/source'), Path('/inputs'), wheel)
        args, options = store.run.call_args
        self.assertIn('--network=none', args[1])
        self.assertIn('--tmpfs=/measure:rw,exec,nosuid,nodev,size=192m,mode=0700', args[1])
        self.assertIn('--env=TMPDIR=/measure', args[1])
        self.assertIn('/source:/work:ro,Z', args[1])
        mounts = [arg for arg in args[1] if ':ro,Z' in arg]
        self.assertEqual(mounts, ['/source:/work:ro,Z', '/inputs:/inputs:ro,Z'])
        self.assertNotIn('payload', options)
        self.assertNotIn('SONAR_TOKEN', ' '.join(args[1] + args[2]))
        self.assertNotIn(suite, args[2][1])
        self.assertEqual(args[2][3:], [suite])

    def test_scanner_token_goes_only_to_stdin(self):
        store = Mock()
        store.run.return_value = (0, f'OK\n{TASK}\n'.encode(), b'')
        secret = b'local-test-token-never-in-argv'
        got = sandbox.scanner(store, Path('/source'), Path('/inputs'), ['fixed=property'], secret)
        args, options = store.run.call_args
        self.assertEqual(got, ['OK', TASK])
        self.assertEqual(options['payload'], secret + b'\n')
        self.assertNotIn(secret.decode(), str(args))
        self.assertIn('/inputs:/inputs:ro,Z', args[1])


class BaselineTest(unittest.TestCase):
    def test_receipt_roundtrip_rejects_link_and_relaxed_permissions(self):
        with TemporaryDirectory() as directory:
            home = Path(directory)
            with state.state_directory(home) as (folder, fd):
                state.record_baseline(folder, fd, {'example': True})
                self.assertEqual(state.read_baseline(folder, fd), {'example': True})
                file = folder / 'main.json'
                file.chmod(0o644)
                with self.assertRaises(PublishError):
                    state.read_baseline(folder, fd)
                file.unlink()
                file.symlink_to(home / 'elsewhere')
                with self.assertRaises(OSError):
                    state.read_baseline(folder, fd)

    def test_published_baseline_is_required_to_match_policy_revision_and_tools(self):
        identity = {'cores': [PATH], 'publisher': HEAD}
        old = {'head': BASE, 'identity': identity, 'policy': {'gate': 1},
               'result': {'analysis': ANALYSIS, 'measures': {PATH: COUNTS}}}
        remote = Mock()
        remote.latest_main.return_value = (ANALYSIS, BASE, SINCE)
        with patch.object(state, 'read_baseline', return_value=old):
            publish.verify_baseline(remote, checkout, REVISION, (None, None), identity, {'gate': 1})
            with self.assertRaises(PublishError):
                publish.verify_baseline(remote, checkout, REVISION, (None, None), identity, {'gate': 2})
            remote.latest_main.return_value = ('later-analysis', BASE, SINCE)
            with self.assertRaises(PublishError):
                publish.verify_baseline(remote, checkout, REVISION, (None, None), identity, {'gate': 1})


if __name__ == '__main__':
    unittest.main()
