"""
django-xss-fuzzer: An XSS vulnerability fuzz tester for Django views.
"""
import os
from collections import namedtuple

from django.db.models import Model, QuerySet
from django.conf import settings
import logging


logger = logging.getLogger(__name__)
__version__ = '0.2.0'
_ENV_VAR_NAME = 'XSS_PATTERN'
_XssPattern = namedtuple('XssPattern', 'string description')


class XssPattern(_XssPattern):
    def __init__(self):
        self._message = None

    def __str__(self):
        return self.string

    @property
    def message(self):
        if self._message:
            return self._message

    def load(self):
        os.environ[_ENV_VAR_NAME] = self.string

    def succeeded(self, selenium):
        logs = list(selenium.get_log('browser'))
        pass_ = any("--PASS--" in entry['message'] for entry in logs)
        success_ = filter(lambda entry: "--SUCCESS" in entry['message'], logs)
        if success_:
            self._message = success_[0]
        return pass_ and not any(success_)


DEFAULT_PATTERNS = (
    XssPattern('<script>throw onerror=eval,\'=console.log\x28\\\'{0}\\\'\x29\'</script>', "Script tag with onerror event"),
    XssPattern('x onafterscriptexecute="console.log(\'{0}\')"',  "non-quoted attribute escape"),
    XssPattern('x onafterscriptexecute="console.log(`{0}`)"',  "non-quoted attribute escape with backticks"),
    XssPattern('<script>console.log(`{0}`)</script>',  "template strings"),
    XssPattern('x onafterprint="console.log(\'{0}\')"',  "non-quoted attribute escape on load"),
    XssPattern('x onerror="console.log(\'{0}\')"',  "non-quoted attribute escape on load"),
    XssPattern('x onafterprint="console.log(`{0}`)"',  "non-quoted attribute escape on load with backticks"),
    XssPattern('+ADw-script+AD4-console.log(+ACc-{0}+ACc-)+ADw-/script+AD4-',  "UTF-7 charset meta"),
    XssPattern('data:text/javascript;base64,Y29uc29sZS5sb2coJy0tU1VDQ0VTU1tdLS0nKQ==',  "JS-encoded base64, payload is '--SUCCESS[]--'")
)


class ViewFuzzerMiddleware:
    """
    Attempts various XSS attacks against the view
    """
    def __init__(self, get_response):
        self.index = 0
        self.get_response = get_response
        self.pattern = getattr(settings, 'XSS_PATTERN', DEFAULT_PATTERNS[self.index].string)
        self.inject_kwargs = getattr(settings, 'XSS_INJECT_KWARGS', False)
        self.inject_context_data = getattr(settings, 'XSS_INJECT_CONTEXT_DATA', True)

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def process_view(self, request, view_func, view_args, view_kwargs):
        if request.method not in ('GET',):  # Just GET for now.
            return None

        # Inject (reflection attack)
        if self.inject_kwargs:
            for key, value in view_kwargs.items():
                if isinstance(value, str):
                    view_kwargs[key] = self._inject_pattern(key)

    def _reflect_model(self, inst, name):
        for key, value in inst.__dict__.items():
            if isinstance(value, str):
                setattr(inst, key,  self._inject_pattern('{0}.{1}'.format(name, key)))

    def process_template_response(self, request, response):
        if not self.inject_context_data:
            return response

        for key, value in response.context_data.items():
            if key == 'view':  # ignore this field
                continue
            if isinstance(value, str):
                response.context_data[key] = self._inject_pattern(key)
            elif isinstance(value, Model):
                self._reflect_model(value, key)
            elif isinstance(value, QuerySet):
                # Exhaust lazy query sets so we can hack the attributes
                _exhausted = list(value)
                for i in _exhausted:
                    self._reflect_model(i, key)
                response.context_data[key] = _exhausted
            # TODO: inject into other types.

        return response

    def _inject_pattern(self, key):
        """
        Inject the value as a XSS-attack string with the name of the field inside
        """
        if _ENV_VAR_NAME in os.environ:
            pattern = os.environ[_ENV_VAR_NAME]
        else:
            pattern = self.pattern

        logger.debug('XSS fuzzer swapping {0} value with {1}'.format(key, pattern))
        return pattern.format('--SUCCESS[{0}]--'.format(key))  # nosec
