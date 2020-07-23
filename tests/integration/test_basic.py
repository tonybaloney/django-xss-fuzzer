import pytest


paths = (
    '/',
    '/basic'
)


@pytest.mark.django_db()
@pytest.mark.parametrize('path', paths)
def test_sample(selenium, live_server, settings, xss_pattern, path):
    setattr(settings, 'XSS_PATTERN', xss_pattern.string)
    selenium.get('%s%s' % (live_server.url, path), )
    assert not xss_pattern.succeeded(selenium), xss_pattern.message
