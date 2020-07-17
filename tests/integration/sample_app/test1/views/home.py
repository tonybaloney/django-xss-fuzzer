from django.views.generic import TemplateView


class HomeView(TemplateView):
    template_name = "home.html"


class BasicContextView(TemplateView):
    template_name = "basic_context.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['sample'] = "Simple String"
        return context
