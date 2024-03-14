"""
A WSGI Application wrapper ("Middleware") to convert Python's logging module
logs to "structured logging" (https://cloud.google.com/logging/docs/structured-logging).
This wrapper integrates the logs with the request trace identifier from App
Engine, so the logs ca be grouped together in the logs viewer (note, that this
must be selected manually in the viewer, by choosing the 'request_log' in the
'correlate by' drop down menu).

This wrapper works without any additional dependencies (no need for the cloud
logging libraries and all its dependencies!). It uses the builtin App Engine
service that exports the stdout/stderr logs to Cloud logging.

Usage:
    from google.appengine.api import wrap_wsgi_app
    from afterburner.logging import StructuredLoggingMiddleware

    app = StructuredLoggingMiddleware(wrap_wsgi_app(<your_wsgi_app>))
"""
import sys
import threading
import logging
import json
from ._internal import get_project_id


# Thread local storage for the cloud trace id
# TODO(tijmen): Probably should use the new contextvars module here to store
# this identifier.
_thread_local_request_data = threading.local()


class StructuredLoggingMiddleware:
    """
    WSGI "Middleware" class that wraps all logs within the request to the
    structured logging form. Ideally this middleware should be as high as
    possible in the chain of WSGI middlewares, so that all logs can be
    correlated to the requests.
    """
    def __init__(self, app, level=None, _stream=None):
        """"
        Args:
            app: The WSGI application that is being wrapped.
            level: Set the log level that will be captured. If not set,
                takes the current level of the root logger.
            _stream: The stream that the logs are output to. Available for
                testing.
        """
        self._app = app
        self._project = get_project_id()

        # Insert the log formatter
        root_logger = logging.getLogger()
        if level is None:
            level = root_logger.level
        # Remove existing handlers to prevent log duplication
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        self._handler = _BufferedStreamHandler(stream=_stream or sys.stdout)
        root_logger.addHandler(self._handler)
        root_logger.setLevel(level)


    def __call__(self, environ, start_response):
        # If there is no trace, we can make one up on our own. However, on
        # App Engine standard, each request should have a trace identifier.
        trace_header = environ.get("HTTP_X_CLOUD_TRACE_CONTEXT")
        if trace_header is None:
            trace_header = _generate_trace_id()
        trace = trace_header.split("/")
        trace_id = f"projects/{self._project}/traces/{trace[0]}"
        # Url & method for log output
        url = _get_url(environ)
        method = environ.get('REQUEST_METHOD', "GET")
        # Create a buffer to capture logs in for this request.
        _thread_local_request_data.log_buffer = []
        _thread_local_request_data.status_code = 0
        # Wrap the response to store the status code in the request local data
        def start_response_wrapper(status, response_headers, exc_info=None):
            status_code = int(str(status).split(' ')[0])
            _thread_local_request_data.status_code = status_code
            return start_response(status, response_headers, exc_info)

        try:
            return self._app(environ, start_response_wrapper)
        finally:
            self._handler.flush_logs(
                    url=url,
                    method=method,
                    trace_id=trace_id,
                    status_code=_thread_local_request_data.status_code)
            delattr(_thread_local_request_data, 'status_code')
            delattr(_thread_local_request_data, 'log_buffer')
            self._handler.flush()


class _BufferedStreamHandler(logging.StreamHandler):
    terminator = '\n'

    def __init__(self, stream=None):
        super().__init__(stream)
        self.formatter = _LogFormatter()

    def emit(self, record):
        # Instead of immediately writing to stdout, buffer the records so we
        # can write them at the end when we have information about the request.
        if hasattr(_thread_local_request_data, 'log_buffer'):
            _thread_local_request_data.log_buffer.append(record)
        else:
            # Not in a request, just emit as usual
            super().emit(record)

    def flush_logs(self, url=None, method=None, trace_id=None, status_code=0):
        """
        Formats and writes all logs in the thread-local buffer to the output
        stream in structured logging format.

        Args:
            trace_id: The Cloud Trace identifier
            status_code: The http status code of the request.
        """
        http_request_data = {
            # Disable these fields as otherwise the url is shown instead of the
            # message in the log viewer.
            # "requestUrl": url,
            # "requestMethod": method,
            "status": status_code,
        }
        # Copy over the buffer in case somehow new logs occur. Those are just
        # discarded then.
        records = list(_thread_local_request_data.log_buffer)
        _thread_local_request_data.log_buffer.clear()
        for record in list(records):
            message = self.formatter.format(record)
            # Output the timestamp of the record, so it shows up in the correct
            # place in traces
            seconds = int(record.created)
            nanoseconds = int((record.created - seconds) * 1_000_000_000)
            entry = {
                "severity": record.levelname,
                "message": message,
                "httpRequest": http_request_data,
                'timestamp': {
                    'seconds': seconds,
                    'nanos': nanoseconds,
                },
                "logging.googleapis.com/trace": trace_id,
                'logging.googleapis.com/sourceLocation': {
                    'file': record.filename,
                    'line': record.lineno,
                    'function': record.funcName,
                }
            }
            self.stream.write(json.dumps(entry) + self.terminator)
        self.flush()


# Custom log formatter to create a plain log messgae without any additional
# information. The extra data is passed in the structured log data.
class _LogFormatter(logging.Formatter):
    def format(self, record):
        message = record.getMessage()
        if record.exc_info:
            if not message.endswith("\n"):
                message += "\n"
            message += self.formatException(record.exc_info)
        if record.stack_info:
            if not message.endswith("\n"):
                message += "\n"
            message += self.formatStack(record.stack_info)
        return message


def _generate_trace_id() -> str:
    import random
    return "%0x" % random.getrandbits(128)


def _get_url(environ):
    """
    Returns the url, including scheme and path as set in the environment
    """
    scheme = environ.get('wsgi.url_scheme', '')
    host = environ.get('HTTP_HOST', '')
    path = environ.get('PATH_INFO', '')
    return f"{scheme}://{host}{path}"
