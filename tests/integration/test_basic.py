import pytest
from django_xss_fuzzer import _DEFAULT_PATTERNS
import os

@pytest.mark.django_db()
def test_home(selenium, live_server):
    selenium.get('%s%s' % (live_server.url, '/'))
    assert any("--PASS--" in entry['message'] for entry in selenium.get_log('browser'))


@pytest.mark.django_db()
@pytest.mark.parametrize('pattern', _DEFAULT_PATTERNS)
def test_sample(selenium, live_server, pattern):
    os.environ['XSS_PATTERN'] = pattern
    selenium.get('%s%s' % (live_server.url, '/basic'))
    logs = list(selenium.get_log('browser'))

    assert any("--PASS--" in entry['message'] for entry in logs)
    assert not any("--SUCCESS" in entry['message'] for entry in logs), "Found XSS vulnerability using {0}".format(pattern)

