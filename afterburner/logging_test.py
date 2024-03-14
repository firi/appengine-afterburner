import unittest
import logging
import http
import json
from io import StringIO

from google.appengine.ext import testbed

from .logging import StructuredLoggingMiddleware, Trace

def log_single_line(environ, start_response, exc_info=None):
    """
    An WSGI "app" that logs a single line.
    """
    logging.info("Test")
    start_response(http.HTTPStatus.OK, [])

def log_multiple_lines(environ, start_response, exc_info=None):
    """
    WSGI "app" that logs multiple lines.
    """
    logging.info("info")
    logging.warning("warning")
    logging.error("error")
    start_response(http.HTTPStatus.OK, [])

def log_exception(environ, start_response, exc_info=None):
    """
    An WSGI "app" that logs an exception and returns a 500 error
    """
    try:
        raise ValueError("Exception description")
    except Exception as e:
        logging.exception(e)
    start_response(http.HTTPStatus.INTERNAL_SERVER_ERROR, [])

def log_exception_deeply_nested(environ, start_response, exc_info=None):
    """
    A WSGI app that logs an exception with a larger stack trace
    """
    def call_back(n):
        recurse_n_times(n)

    def recurse_n_times(n):
        if n > 0:
            # Called through a separate function to prevent stack trace
            # compression
            call_back(n - 1)
        else:
            raise ValueError("Exception at the bottom of the stack")

    try:
        recurse_n_times(10)
    except Exception as e:
        logging.exception(e)
    start_response(http.HTTPStatus.INTERNAL_SERVER_ERROR, [])


def start_response_noop(self, status, response_headers, exc_info=None):
    """A no-op start_response callable for testing"""


class LoggingTest(unittest.TestCase):
    def setUp(self):
        # We need an environment to get the project id
        self.testbed = testbed.Testbed()
        self.testbed.setup_env(app_id='afterburner', overwrite=True)
        self.testbed.activate()
        self.environ = {}
        self.environ["HTTP_X_CLOUD_TRACE_CONTEXT"] = "trace_identifier/76614586407295139;o=1"
        self.environ["PATH_INFO"] = "/path/test"
        # Store the log handlers and level
        self.saved_handlers = logging.root.handlers[:]
        self.saved_level = logging.root.level

    def tearDown(self):
        self.testbed.deactivate()
        # Restore log handlers
        logging.root.handlers[:] = self.saved_handlers
        logging.root.setLevel(self.saved_level)

    def test_log_single_line(self):
        stream = StringIO()
        app = StructuredLoggingMiddleware(log_single_line,
                                          _stream=stream,
                                          level=logging.INFO)
        app(self.environ, start_response_noop)
        log_entries = _read_log(stream)
        self.assertEqual(len(log_entries), 1)

        log_entry = log_entries[0]
        # Assert that the log entry contains expected structured fields
        self.assertIn("message", log_entry)
        self.assertEqual(log_entry["message"], "Test")
        self.assertIn("httpRequest", log_entry)
        self.assertEqual(log_entry["httpRequest"]["status"], 200)
        self.assertEqual(log_entry["logging.googleapis.com/trace"],
                         "projects/afterburner/traces/trace_identifier")
        self.assertGreater(log_entry["timestamp"]["seconds"], 0)
        self.assertGreater(log_entry["timestamp"]["nanos"], 0)
        self.assertEqual(log_entry["logging.googleapis.com/spanId"],
                         "110308f776b98a3")
        self.assertTrue(log_entry["logging.googleapis.com/trace_sampled"])


    def test_log_multiple_lines(self):
        stream = StringIO()
        app = StructuredLoggingMiddleware(log_multiple_lines,
                                          _stream=stream,
                                          level=logging.INFO)
        app(self.environ, start_response_noop)
        log_entries = _read_log(stream)
        self.assertEqual(len(log_entries), 3)  # Expecting three log entries

        expected_messages = ["info", "warning", "error"]
        for log_entry, expected_message in zip(log_entries, expected_messages):
            self.assertEqual(log_entry["message"], expected_message)
            self.assertEqual(log_entry["httpRequest"]["status"], 200)
            self.assertEqual(log_entry["logging.googleapis.com/trace"],
                             "projects/afterburner/traces/trace_identifier")

    def test_log_exception(self):
        stream = StringIO()
        app = StructuredLoggingMiddleware(log_exception,
                                          _stream=stream,
                                          level=logging.INFO)
        app(self.environ, start_response_noop)
        log_entries = _read_log(stream)
        self.assertEqual(len(log_entries), 1)
        log_entry = log_entries[0]
        self.assertIn("Exception description", log_entry["message"])
        self.assertEqual(log_entry["httpRequest"]["status"], 500)
        self.assertEqual(log_entry["logging.googleapis.com/trace"],
                        "projects/afterburner/traces/trace_identifier")


    def test_log_exception_larger_stack(self):
        stream = StringIO()
        app = StructuredLoggingMiddleware(log_exception_deeply_nested,
                                          _stream=stream,
                                          level=logging.INFO)
        app(self.environ, start_response_noop)
        log_entry = _read_log(stream)[0]



def _read_log(stream):
    """
    Read the stream and returned JSON decoded log entries. Each line should
    have a single JSON payload.
    """
    logs = stream.getvalue()
    log_entries = logs.strip().split("\n")
    return [json.loads(entry) for entry in log_entries]


class TraceTest(unittest.TestCase):
    def test_empty_string(self):
        trace = Trace.parsed_from_header("")
        self.assertEqual(trace.trace_id, "")
        self.assertIsNone(trace.span_id)
        self.assertFalse(trace.sampled)

    def test_span_integer_value(self):
        """
        Integer spans must be converted to hexadecimal values.
        """
        trace = Trace.parsed_from_header("trace/123456/something")
        self.assertEqual(trace.trace_id, "trace")
        self.assertEqual(trace.span_id, "1e240")

    def test_multiple_slashes(self):
        trace = Trace.parsed_from_header("trace/span/something")
        self.assertEqual(trace.trace_id, "trace")
        self.assertEqual(trace.span_id, "span")
        self.assertFalse(trace.sampled)

    def test_sampled(self):
        trace = Trace.parsed_from_header("trace/span;o=1")
        self.assertEqual(trace.trace_id, "trace")
        self.assertEqual(trace.span_id, "span")
        self.assertTrue(trace.sampled)

    def test_no_span(self):
        trace = Trace.parsed_from_header("trace")
        self.assertEqual(trace.trace_id, "trace")
        self.assertIsNone(trace.span_id)
        self.assertFalse(trace.sampled)

    def test_no_span_sampled(self):
        trace = Trace.parsed_from_header("trace;o=1")
        self.assertEqual(trace.trace_id, "trace")
        self.assertIsNone(trace.span_id)
        self.assertTrue(trace.sampled)




if __name__ == '__main__':
    unittest.main()
