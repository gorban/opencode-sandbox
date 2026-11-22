"""Read-only Cloud/GitHub confirmation of the publisher's exact analysis."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit

from sonar_checkout import REPOSITORY
from sonar_exec import PublishError, capture


ORGANIZATION = 'gorban'
PROJECT = 'gorban_opencode-sandbox'
SONAR = 'https://sonarcloud.io'
TASK_ID = re.compile(r'[A-Za-z0-9_-]{10,90}')
ANALYSIS_ID = re.compile(r'[A-Za-z0-9_-]{10,90}')
SKEW = timedelta(seconds=10)
METRICS = 'lines_to_cover,uncovered_lines,conditions_to_cover,uncovered_conditions'


def download(url, limit, *, mode='api'):
    tooling = Path(__file__).resolve().parent
    status, body, diagnostic = capture(
        [sys.executable, '-IB', str(tooling / 'sonar_http.py'), url, str(limit), mode],
        cwd=tooling, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, timeout=12, limit=limit + 8,
    )
    if status == 1 and re.fullmatch(rb'[345]\d{2}\n', diagnostic):
        raise HTTPError(url, int(diagnostic), 'Publisher API request failed', None, None)
    if status or diagnostic or len(body) > limit:
        raise PublishError('Publisher API request failed or exceeded the response limits')
    return body


def github(endpoint):
    return json.loads(download(f'https://api.github.com/repos/{REPOSITORY}/{endpoint}', 2_000_000))


def sonar(endpoint, **params):
    return json.loads(download(f'{SONAR}/api/{endpoint}?' + urlencode(params), 2_000_000))


def stamp(value):
    result = datetime.fromisoformat(value)
    if result.tzinfo is None:
        raise PublishError('Remote timestamp lacks a time zone')
    return result


def mode_policy():
    navigation = sonar('navigation/component', component=PROJECT)
    gate_id = navigation['qualityGate']['key']
    policy = sonar('qualitygates/show', id=gate_id, organization=ORGANIZATION)
    conditions = sorted((c['metric'], c['op'], c['error']) for c in policy['conditions'])
    if (policy['id'] != gate_id or ('new_coverage', 'LT', '100') not in conditions
            or ('new_violations', 'GT', '0') not in conditions):
        raise PublishError('Sonar project does not have the reviewed coverage and issue policies')
    settings = sonar('settings/values', component=PROJECT,
                     keys='sonar.leak.period,sonar.qualitygate.ignoreSmallChanges')['settings']
    code_period = next((s for s in settings if s['key'] == 'sonar.leak.period'), None)
    if not code_period or not code_period.get('value'):
        raise PublishError('Could not verify the Sonar new-code definition')
    policy = {'gate': gate_id, 'conditions': [list(c) for c in conditions],
              'settings': sorted(settings, key=lambda setting: setting['key'])}
    return navigation['autoscanEnabled'], policy


def latest_main():
    latest = sonar('project_analyses/search', project=PROJECT, branch='main', ps=1)['analyses']
    if not latest:
        raise PublishError('Sonar has no published main analysis')
    return latest[0]['key'], latest[0]['revision'], stamp(latest[0]['date'])


def context(revision):
    return {'branch': 'main'} if revision.number is None else {'pullRequest': revision.number}


def task_snapshot(revision, task, since):
    result = sonar('ce/component', component=PROJECT, **context(revision))
    if any(item['id'] != task for item in result['queue']):
        raise PublishError('A competing Sonar analysis was queued during publication')
    current = result.get('current')
    if current is None:
        return None
    if current['id'] != task:
        raise PublishError('A different Sonar task is current')
    if current['status'] != 'SUCCESS' or current['componentKey'] != PROJECT:
        raise PublishError('The exact Sonar task did not complete successfully')
    branch, pr = current.get('branch'), current.get('pullRequest')
    if revision.number is None:
        valid = branch == 'main' and pr is None
    else:
        valid = str(pr) == str(revision.number)
    if not valid or not ANALYSIS_ID.fullmatch(current.get('analysisId', '')):
        raise PublishError('Sonar task has the wrong branch, PR or analysis ID')
    submitted, started, executed = (stamp(current[k]) for k in ('submittedAt', 'startedAt', 'executedAt'))
    if not since - SKEW <= submitted <= started <= executed:
        raise PublishError('Sonar task timestamps do not match this submission')
    return current['analysisId'], executed


def pr_identity(revision):
    requests = sonar('project_pull_requests/list', project=PROJECT)['pullRequests']
    item = next((item for item in requests if item['key'] == str(revision.number)), None)
    if (not item or item['branch'] != revision.branch or item['target'] != 'main'
            or (item.get('commit') or {}).get('sha') != revision.head):
        raise PublishError('Sonar PR analysis does not identify the approved revision')
    return item['commit']['sha'], stamp(item['analysisDate'])


def analysis_identity(revision, analysis_id, since, executed):
    if revision.number is None:
        key, sha, date = latest_main()
        if key != analysis_id:
            raise PublishError('Sonar main analysis was superseded')
    else:
        sha, date = pr_identity(revision)
    # Sonar's analysis date can be the client scan timestamp, prior to CE submission.
    if sha != revision.head or not since - SKEW <= date <= executed + SKEW:
        raise PublishError('Sonar analysis revision or timing did not match this scan')
    return sha, date


def verify_metrics(revision, expected, required):
    verified = {}
    for path, counts in expected.items():
        try:
            result = sonar('measures/component', component=f'{PROJECT}:{path}', metricKeys=METRICS,
                           **context(revision))['component']
        except HTTPError as error:
            error.close()
            if error.code == 404 and path not in required:
                continue
            raise
        actual = {m['metric']: int(m['value']) for m in result['measures']}
        for metric in ('conditions_to_cover', 'uncovered_conditions'):
            actual.setdefault(metric, 0)
        if result['path'] != path or actual != counts:
            raise PublishError(f'Sonar did not import the expected coverage counters for {path}')
        verified[path] = actual
    return verified


def gate_for(revision, analysis_id, expected_gate):
    gate = sonar('qualitygates/project_status', analysisId=analysis_id)['projectStatus']
    if gate['status'] != expected_gate:
        raise PublishError('Published gate does not match the scanner result')
    if revision.number is not None:
        condition = next((c for c in gate['conditions'] if c['metricKey'] == 'new_coverage'), None)
        if (gate.get('ignoredConditions') or not condition or condition.get('errorThreshold') != '100'
                or condition.get('comparator') != 'LT' or condition['status'] not in ('OK', 'ERROR')):
            raise PublishError('PR coverage condition is absent, waived or uncomputed')
        value = Decimal(condition['actualValue'])
        if (not value.is_finite() or not 0 <= value <= 100
                or (value == 100) != (condition['status'] == 'OK')
                or (expected_gate == 'OK' and value != 100)):
            raise PublishError('Computed PR coverage does not match the native gate result')
    return gate


def check_context(check, revision):
    details = urlsplit(check.get('details_url') or '')
    fields = parse_qs(details.query)
    return (details.scheme == 'https' and details.netloc == 'sonarcloud.io'
            and fields.get('id') == [PROJECT] and fields.get('pullRequest') == [str(revision.number)])


def latest_native_check(revision):
    filters = urlencode({'check_name': 'SonarCloud Code Analysis', 'app_id': 12526,
                         'filter': 'all', 'per_page': 100})
    result = github(f'commits/{revision.head}/check-runs?{filters}')
    if result['total_count'] > len(result['check_runs']):
        raise PublishError('Could not inventory the existing native GitHub checks')
    native = [c for c in result['check_runs'] if c['name'] == 'SonarCloud Code Analysis'
              and c['app']['id'] == 12526 and c['head_sha'] == revision.head
              and check_context(c, revision)]
    return max(native, key=lambda c: c['id'], default=None)


def native_check_id(revision):
    current = latest_native_check(revision)
    return current['id'] if current else 0


def wait_for_check(revision, gate, since, previous_id):
    expected = 'success' if gate == 'OK' else 'failure'
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        last = latest_native_check(revision)
        if last and last['id'] > previous_id and last['status'] == 'completed' and last['completed_at']:
            if stamp(last['completed_at']) >= since.replace(microsecond=0):
                if last['conclusion'] != expected:
                    raise PublishError('Native GitHub check disagrees with the computed Sonar gate')
                return last['html_url']
        time.sleep(10)
    raise PublishError('A fresh native GitHub check was not observed on the approved revision')


def confirm(revision, output, since, counts, required, previous_check_id):
    if len(output) != 2 or output[0] not in ('OK', 'ERROR') or not TASK_ID.fullmatch(output[1]):
        raise PublishError('Scanner did not emit a valid task receipt')
    gate, task = output
    observed = task_snapshot(revision, task, since)
    if observed is None:
        raise PublishError('Sonar did not expose the completed scanner task for verification')
    analysis_id, executed = observed
    identity = analysis_identity(revision, analysis_id, since, executed)
    result = gate_for(revision, analysis_id, gate)
    matched = verify_metrics(revision, counts, required)
    check = wait_for_check(revision, gate, since, previous_check_id) if revision.number else None
    now = task_snapshot(revision, task, since)
    if ((now is not None and now != observed)
            or analysis_identity(revision, analysis_id, since, executed) != identity):
        raise PublishError('Sonar analysis identity changed during verification')
    coverage = next((c.get('actualValue') for c in result['conditions']
                     if c['metricKey'] == 'new_coverage'), None)
    return {'task': task, 'analysis': analysis_id, 'gate': gate, 'new_coverage': coverage,
            'measures': matched, 'check': check, 'date': identity[1].isoformat()}


def now():
    return datetime.now(timezone.utc)
