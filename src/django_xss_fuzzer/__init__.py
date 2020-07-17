"""
django-xss-fuzzer: An XSS vulnerability fuzz tester for Django views.
"""
import os

from django.db.models import Model, QuerySet
from django.conf import settings
import logging


logger = logging.getLogger(__name__)
__version__ = '0.1.0'

_DEFAULT_PATTERNS = (
    '<script>throw onerror=eval,\'=console.log\x28\\\'{0}\\\'\x29\'</script>',
    'x onafterscriptexecute="console.log(\'{0}\')"',  # non-quoted attribute escape
    'x onafterscriptexecute="console.log(`{0}`)"',  # non-quoted attribute escape with backticks
    '<script>console.log(`{0}`)</script>',  # template strings
    'x onafterprint="console.log(\'{0}\')"',  # non-quoted attribute escape on load
    'x onerror="console.log(\'{0}\')"',  # non-quoted attribute escape on load
    'x onafterprint="console.log(`{0}`)"',  # non-quoted attribute escape on load with backticks
    '+ADw-script+AD4-console.log(+ACc-{0}+ACc-)+ADw-/script+AD4-',  # UTF-7 charset meta
    'data:text/javascript;base64,Y29uc29sZS5sb2coJy0tU1VDQ0VTU1tdLS0nKQ==',  # JS-encoded base64, payload is '--SUCCESS[]--'
)


class ViewFuzzerMiddleware:
    """
    Attempts various XSS attacks against the view
    """
    def __init__(self, get_response):
        self.index = 0
        self.get_response = get_response
        self.patterns = getattr(settings, 'XSS_FUZZER_PATTERNS', _DEFAULT_PATTERNS)
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
            if isinstance(value, Model):
                self._reflect_model(value, key)
            if isinstance(value, QuerySet):
                # Exhaust lazy query sets so we can hack the attributes
                _exhausted = list(value)
                for i in _exhausted:
                    self._reflect_model(i, key)
                response.context_data[key] = _exhausted
            # TODO: inject into other types.

        return response

    def _inject_pattern(self, key):
        '''
        Inject the value as a XSS-attack string with the name of the field inside
        '''
        if 'XSS_PATTERN' in os.environ:
            pattern = os.environ['XSS_PATTERN']
        else:
            pattern = self.patterns[self.index]

        logger.debug('XSS fuzzer swapping {0} value with {1}'.format(key, pattern))
        return pattern.format('--SUCCESS[{0}]--'.format(key))  # nosec
