# Django XSS Fuzzer

An XSS vulnerability fuzz tester for Django views.

## Installation

Install via pip

```console
$ pip install django-xss-fuzzer
```

Add `ViewFuzzerMiddleware` to your middleware list for a **test environment**.

```python
MIDDLEWARE = [
    ...
    'django_xss_fuzzer.ViewFuzzerMiddleware'
]
```

**Do not deploy this to a production server!**

## Configuration

`XSS_FUZZER_PATTERNS` : A list of XSS patterns to try. See [XSS Cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) for inspiration.
`XSS_INJECT_KWARGS` (Default False) : A switch to disable injecting XSS view function keyword arguments
`XSS_INJECT_CONTEXT_DATA` (Default True) : A switch to disable injecting XSS into class data