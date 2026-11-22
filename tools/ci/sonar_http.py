"""Child process for one bounded request to a publisher trust anchor."""

from contextlib import closing
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from runpy import run_path
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit


def api_host(host):
    if host == 'api.github.com':
        return 'api.github.com'
    if host == 'sonarcloud.io':
        return 'sonarcloud.io'
    raise ValueError('Unexpected publisher API host')


def request(url, limit, mode='api'):
    parsed = urlsplit(url)
    path = parsed.path or '/'
    if parsed.scheme != 'https' or path.startswith('//'):
        raise ValueError('Unexpected publisher request target')
    headers = {'User-Agent': 'opencode-sandbox-sonar-publisher'}
    if mode == 'wheel':
        wheel = run_path(str(Path(__file__).with_name('core_coverage.py')))['WHEEL']
        if url != wheel or parsed.netloc != 'files.pythonhosted.org':
            raise ValueError('Unexpected coverage wheel URL')
        host = 'files.pythonhosted.org'
    elif mode == 'api':
        host = api_host(parsed.netloc)
        headers['Accept'] = 'application/json'
    else:
        raise ValueError('Unexpected publisher request mode')

    # Connect to a fixed HTTPS origin and send only the path and query.
    target = f'{path}?{parsed.query}' if parsed.query else path
    with closing(HTTPSConnection(host, timeout=12)) as connection:
        connection.request('GET', target, headers=headers)
        with connection.getresponse() as response:
            if 300 <= response.status < 600:
                raise HTTPError(url, response.status, 'Publisher API request failed', None, None)
            if response.status != 200:
                raise ValueError('Unexpected publisher API status')
            data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Publisher response exceeded the byte limit')
    return data


if __name__ == '__main__':
    try:
        sys.stdout.buffer.write(request(sys.argv[1], int(sys.argv[2]), sys.argv[3]))
    except HTTPError as error:
        # The parent uses 404 to distinguish an analysis that is still pending.
        print(error.code, file=sys.stderr)
        error.close()
        sys.exit(1)
    except (HTTPException, OSError, ValueError):
        sys.exit(2)
