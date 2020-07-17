import pytest


@pytest.mark.django_db()
def test_home(selenium, live_server):
    selenium.get('%s%s' % (live_server.url, '/'))
    assert any("--PASS--" in entry['message'] for entry in selenium.get_log('browser'))


@pytest.mark.django_db()
def test_sample(selenium, live_server):
    selenium.get('%s%s' % (live_server.url, '/basic'))
    logs = list(selenium.get_log('browser'))
    assert any("--PASS--" in entry['message'] for entry in logs)
    assert any("--SUCCESS" in entry['message'] for entry in logs)
