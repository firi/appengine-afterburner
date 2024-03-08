"""
Various classes to help setting up a WSGI application. 1st gen App Engine
allowed for multiple applications that were specified in app.yaml, but 2nd
gen App Engine only has a single WSGI application as entry point (by default
the main.py:app).

The WSGICombiner allows to bundle all separate WSGI applications into a single
WSGI Application that can act as the entry point. The main difference with
the previous app.yaml setup is that routing to the separate applications is done
through path prefixes (so no regular expressions).

For example:

from afterburner.wsgi import WSGICombiner

app = WSGICombiner(default_application,  {
    '/api': api.application,
    '/admin': admin.application,
})
"""


class WSGICombiner:
    """
    Combines multiple applications as a single WSGI application.

    Args:
        app: The default WSGI application that requests are routed to if they
            do not match any of the other routes.
        routes: A dictionary of strings to WSGI applications. Each
            string must be a prefix of the path. More specific prefixes are
            preferred (ie. a path that matches /app/test is preferred above
            a /app prefix).
    """
    def __init__(self, app, routes):
        if not routes:
            routes = {}
        for prefix, _ in routes.items():
            if not prefix.startswith("/"):
                raise ValueError(f"Path prefixes must start with a slash. "
                                 f"Got '{prefix} instead.")
            if len(prefix) > 1 and prefix.endswith("/"):
                raise ValueError(
                    f"Path prefixes cannot end with a trailing slash. Remove "
                    f"the last slash from '{prefix}' to fix the problem.")
        self.app = app
        self.routes = routes

    def __call__(self, environ, start_response):
        script_name = environ.get("SCRIPT_NAME", "")
        path = environ.get("PATH_INFO", "")
        path_info = ""
        while path.startswith("/"):
            app = self.routes.get(path)
            if app is not None:
                break
            path, remainder = path.rsplit("/", 1)
            path_info = f"/{remainder}{path_info}"
        else:
            app = self.app
        environ["SCRIPT_NAME"] = script_name + path
        environ["PATH_INFO"] = path_info
        return app(environ, start_response)
