from django_xss_fuzzer import DEFAULT_PATTERNS


def pytest_generate_tests(metafunc):
    if "xss_pattern" in metafunc.fixturenames:
        metafunc.parametrize("xss_pattern", DEFAULT_PATTERNS)


def pytest_make_parametrize_id(config, val, argname):
    if argname == "xss_pattern":
        return val.description
