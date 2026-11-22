"""Child process for one bounded request to a publisher trust anchor."""

from pathlib import Path
from runpy import run_path
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


class RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def request(url, limit, mode='api'):
    headers = {'User-Agent': 'opencode-sandbox-sonar-publisher'}
    if mode == 'wheel':
        wheel = run_path(str(Path(__file__).with_name('core_coverage.py')))['WHEEL']
        if url != wheel:
            raise ValueError('Unexpected coverage wheel URL')
    elif mode == 'api':
        parsed = urlsplit(url)
        if parsed.scheme != 'https' or parsed.netloc not in {'api.github.com', 'sonarcloud.io'}:
            raise ValueError('Unexpected publisher API URL')
        headers['Accept'] = 'application/json'
    else:
        raise ValueError('Unexpected publisher request mode')
    opener = build_opener(ProxyHandler({}), RejectRedirect())
    req = Request(url, headers=headers)
    with opener.open(req, timeout=12) as response:
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
        sys.exit(1)
    except (OSError, ValueError):
        sys.exit(2)
