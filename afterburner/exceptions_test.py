import unittest
from .exceptions import RequestFailedError

class ExceptionsTest(unittest.TestCase):
    def test_no_http_status_code(self):
        error = RequestFailedError(exception=ValueError("test"))
        self.assertEqual(error.http_status_code, 0)

    def test_http_status_code_no_message(self):
        error = RequestFailedError(http_status_code=500)
        self.assertEqual(error.http_status_code, 500)
