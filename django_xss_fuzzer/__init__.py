"""
django-xss-fuzzer: An XSS vulnerability fuzz tester for Django views.
"""

from random import choice

from django.db.models import Model, QuerySet
from django.conf import settings

__version__ = '0.1.0'

_DEFAULT_PATTERNS = (
    '<script>throw onerror=eval,\'=console.log\x28\\\'found script-based xss in {0}\\\'\x29\'</script>',
    'x onafterscriptexecute=console.log(\'found attribute-based xss in {0}\')')


class ViewFuzzerMiddleware:
    """
    Attempts various XSS attacks against the view
    """
    def __init__(self, get_response):
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
        return choice(self.patterns).format(key)  # nosec
