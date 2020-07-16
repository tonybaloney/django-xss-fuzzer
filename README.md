# Django XSS Fuzzer

An XSS vulnerability fuzz tester for Django views.

This tester will inject XSS patterns into the context data for a template before it is rendered, including:

- Simple strings
- Attributes of Django ORM objects in QuerySets

The goal of this tool is to quickly find any XSS vulnerabilities in Django templates.

Any successful injections will write a message to the browser JavaScript console.

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

Configure the middleware via the Django global settings.

* `XSS_FUZZER_PATTERNS` : A list of XSS patterns to try. See [XSS Cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) for inspiration.
* `XSS_INJECT_KWARGS` (Default False) : A switch to disable injecting XSS view function keyword arguments
* `XSS_INJECT_CONTEXT_DATA` (Default True) : A switch to disable injecting XSS into class data

## What about Django's builtin XSS protection?

In 99% of cases, Django will sanitize the injection strings and they will be unsuccessful.

However, there are some limitations, such as unquoted expressions of HTML tag attributes

```html
<style class={{ var }}>...</style>
```

This extension would automatically replace `var` with `x onafterscriptexecute=console.log('found attribute-based xss in {0}')`.

Django would render the following HTML:

```html
<style class=x onafterscriptexecute=console.log('found attribute-based xss in {0}')>...</style>
```

The JavaScript code within the onafterscriptexecute would be run by the browser, demonstrating the vulnerability.

Other examples, would be the use of the `|safe` filter inside the Django template. This filter can be put into Django views without a full-understanding of the ramifications.

For example, in a permanent XSS attack, the database, or memory state could contain a dangerous string.