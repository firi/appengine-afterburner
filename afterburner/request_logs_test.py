"""Tests for afterburner.request_logs module."""
import json
import unittest
from datetime import datetime, timedelta

from google.appengine.ext import testbed
from google.appengine.api import memcache

from afterburner import request_logs


class RequestLogsClientTest(unittest.TestCase):
    """Test cases for request logs client."""

    def setUp(self):
        """Set up test environment."""
        # Set up testbed
        self.testbed = testbed.Testbed()
        self.testbed.setup_env(app_id='testapp', overwrite=True)
        self.testbed.activate()
        self.testbed.init_memcache_stub()
        self.testbed.init_app_identity_stub()
        self.testbed.init_urlfetch_stub(urlmatchers=[
            self._make_logging_urlmatcher(),
        ])
        # Create client
        self.client = request_logs.Client()

    def tearDown(self):
        """Clean up."""
        self.testbed.deactivate()

    def _make_logging_urlmatcher(self):
        """Create URL matcher for Cloud Logging API."""
        def match_url(url):
            return "logging.googleapis.com/v2/entries:list" in url

        def handle_request(url, payload, method, headers, request, response, **kwargs):
            request_data = json.loads(payload) if payload else {}

            # Return both request logs and app logs together
            response.StatusCode = 200
            response.Content = json.dumps({
                'entries': [
                    # Request log entry
                    {
                        'timestamp': '2024-01-01T12:00:00.000Z',
                        'protoPayload': {
                            '@type': 'type.googleapis.com/google.appengine.logging.v1.RequestLog',
                            'method': 'GET',
                            'resource': '/api/test',
                            'status': 200,
                            'latency': '0.123s',
                            'requestSize': '256',
                            'responseSize': '1024',
                            'userAgent': 'Mozilla/5.0 Test Browser',
                            'ip': '1.2.3.4',
                            'line': [
                                {
                                    'time': '2024-01-01T12:00:00.100Z',
                                    'severity': 'INFO',
                                    'logMessage': 'This request caused a new process to be started.'
                                }
                            ]
                        },
                        'resource': {
                            'type': 'gae_app',
                            'labels': {
                                'module_id': 'default',
                                'version_id': 'v1'
                            }
                        },
                        'trace': 'projects/testapp/traces/trace123'
                    },
                    # App logs for the first request
                    {
                        'timestamp': '2024-01-01T12:00:01.123Z',
                        'severity': 'INFO',
                        'textPayload': 'Processing request',
                        'trace': 'projects/testapp/traces/trace123',
                        'sourceLocation': {
                            'file': 'main.py',
                            'line': 42,
                            'function': 'process_request'
                        },
                        'resource': {
                            'type': 'gae_app',
                            'labels': {
                                'module_id': 'default',
                                'version_id': 'v1'
                            }
                        }
                    },
                    {
                        'timestamp': '2024-01-01T12:00:01.456Z',
                        'severity': 'WARNING',
                        'textPayload': 'Slow query detected',
                        'trace': 'projects/testapp/traces/trace123',
                        'sourceLocation': {
                            'file': 'db.py',
                            'line': 123,
                            'function': 'execute_query'
                        },
                        'resource': {
                            'type': 'gae_app',
                            'labels': {
                                'module_id': 'default',
                                'version_id': 'v1'
                            }
                        }
                    },
                    # Second request log entry (no app logs for this one)
                    {
                        'timestamp': '2024-01-01T11:59:00.000Z',
                        'protoPayload': {
                            '@type': 'type.googleapis.com/google.appengine.logging.v1.RequestLog',
                            'method': 'POST',
                            'resource': '/api/error',
                            'status': 500,
                            'latency': '0.456s',
                            'requestSize': '512',
                            'responseSize': '256',
                            'userAgent': 'curl/7.0',
                            'ip': '4.3.2.1'
                        },
                        'resource': {
                            'type': 'gae_app',
                            'labels': {
                                'module_id': 'default',
                                'version_id': 'v1'
                            }
                        },
                        'trace': 'projects/testapp/traces/trace456'
                    }
                ],
                'nextPageToken': 'token123'
            }).encode('utf-8')

        return (match_url, handle_request)


    def test_fetch_logs_basic(self):
        """Test basic log fetching."""
        # Fetch logs from the last hour
        cursor = request_logs.Cursor(max_age=timedelta(hours=1))
        logs, next_cursor = self.client.fetch_request_logs(cursor)

        # Should return 2 request logs
        self.assertEqual(len(logs), 2)

        # Check first log
        log1 = logs[0]
        self.assertEqual(log1.method, 'GET')
        self.assertEqual(log1.resource, '/api/test')
        self.assertEqual(log1.status, 200)
        self.assertEqual(log1.latency_seconds, 0.123)
        self.assertEqual(log1.trace_id, 'trace123')

        # Should have both embedded and app logs in the logs list
        self.assertEqual(len(log1.logs), 3)  # 1 embedded + 2 app logs

        # Check embedded log (should be first since it has earlier timestamp)
        embedded_log = [log for log in log1.logs if log.is_embedded][0]
        self.assertEqual(embedded_log.severity, 'INFO')
        self.assertEqual(embedded_log.message, 'This request caused a new process to be started.')

        # Check app logs
        app_logs = [log for log in log1.logs if not log.is_embedded]
        self.assertEqual(len(app_logs), 2)
        self.assertEqual(app_logs[0].severity, 'INFO')
        self.assertEqual(app_logs[0].message, 'Processing request')
        self.assertEqual(app_logs[1].severity, 'WARNING')
        self.assertEqual(app_logs[1].message, 'Slow query detected')

        # Check calculated severity (should be WARNING from app logs)
        self.assertEqual(log1.severity, 'WARNING')

        # Check second log
        log2 = logs[1]
        self.assertEqual(log2.method, 'POST')
        self.assertEqual(log2.resource, '/api/error')
        self.assertEqual(log2.status, 500)
        self.assertEqual(log2.trace_id, 'trace456')

        # Should have no logs
        self.assertEqual(len(log2.logs), 0)
        # No logs means no severity
        self.assertIsNone(log2.severity)

        # Check pagination cursor
        self.assertIsNotNone(next_cursor)
        self.assertEqual(next_cursor._page_token, 'token123')

    def test_fetch_logs_with_filters(self):
        """Test log fetching with filters."""
        # Test with service filter
        cursor = request_logs.Cursor(max_age=timedelta(hours=1), service='backend')
        logs, next_cursor = self.client.fetch_request_logs(cursor)
        # Should still work (our mock doesn't filter, but API call should be made)
        self.assertIsNotNone(logs)

        # Test with status filter
        cursor = request_logs.Cursor(max_age=timedelta(hours=1), status_filter='5xx')
        logs, next_cursor = self.client.fetch_request_logs(cursor)
        self.assertIsNotNone(logs)

        # Test with path filter
        cursor = request_logs.Cursor(max_age=timedelta(hours=1), path_filter='/api/*')
        logs, next_cursor = self.client.fetch_request_logs(cursor)
        self.assertIsNotNone(logs)

        # Test with severity filter
        cursor = request_logs.Cursor(max_age=timedelta(hours=1), min_severity='WARNING')
        logs, next_cursor = self.client.fetch_request_logs(cursor)
        self.assertIsNotNone(logs)


    def test_request_log_parsing(self):
        """Test RequestLog class parsing."""
        entry = {
            'timestamp': '2024-01-01T12:00:00.000Z',
            'protoPayload': {
                'method': 'GET',
                'resource': '/test',
                'status': 200,
                'latency': '0.100s',
                'requestSize': '100',
                'responseSize': '200',
                'userAgent': 'Test',
                'ip': '1.2.3.4'
            },
            'resource': {
                'labels': {
                    'module_id': 'default',
                    'version_id': 'v1'
                }
            },
            'trace': 'projects/test/traces/abc123'
        }

        log = request_logs.RequestLog(entry, 'testproject')

        self.assertEqual(log.method, 'GET')
        self.assertEqual(log.resource, '/test')
        self.assertEqual(log.status, 200)
        self.assertEqual(log.latency_seconds, 0.1)
        self.assertEqual(log.service, 'default')
        self.assertEqual(log.version, 'v1')
        self.assertEqual(log.trace_id, 'abc123')
        self.assertEqual(log.project_id, 'testproject')

    def test_log_message_parsing(self):
        """Test LogMessage class parsing for app logs."""
        entry = {
            'timestamp': '2024-01-01T12:00:00.123Z',
            'severity': 'WARNING',
            'textPayload': 'Test warning message',
            'sourceLocation': {
                'file': 'test.py',
                'line': 42,
                'function': 'test_func'
            }
        }

        log = request_logs.LogMessage(entry=entry)

        self.assertEqual(log.severity, 'WARNING')
        self.assertEqual(log.message, 'Test warning message')
        self.assertEqual(log.file, 'test.py')
        self.assertEqual(log.line, 42)
        self.assertEqual(log.function, 'test_func')
        self.assertFalse(log.is_embedded)

    def test_embedded_log_message_parsing(self):
        """Test LogMessage class parsing for embedded logs."""
        line_entry = {
            'time': '2024-01-01T12:00:08.966914Z',
            'severity': 'INFO',
            'logMessage': 'This request caused a new process to be started.'
        }

        log = request_logs.LogMessage(line_entry=line_entry)

        self.assertEqual(log.severity, 'INFO')
        self.assertEqual(log.message, 'This request caused a new process to be started.')
        # System-generated logs don't have source location
        self.assertEqual(log.file, '')
        self.assertEqual(log.line, 0)
        self.assertEqual(log.function, '')
        self.assertTrue(log.is_embedded)

    def test_parse_timestamp(self):
        """Test timestamp parsing."""
        # Test valid RFC3339 timestamp
        ts = request_logs._parse_timestamp('2024-01-01T12:00:00.123Z')
        self.assertEqual(ts.year, 2024)
        self.assertEqual(ts.month, 1)
        self.assertEqual(ts.day, 1)
        self.assertEqual(ts.hour, 12)
        # Test without Z suffix
        ts = request_logs._parse_timestamp('2024-01-01T12:00:00.123')
        self.assertEqual(ts.year, 2024)
        # Test empty string
        with self.assertRaises(ValueError):
            request_logs._parse_timestamp("")
        # Test invalid timestamp
        with self.assertRaises(ValueError):
            request_logs._parse_timestamp('invalid')

    def test_severity_calculation(self):
        """Test that severity is correctly calculated from logs."""
        # Create a request log entry
        entry = {
            'timestamp': '2024-01-01T12:00:00.000Z',
            'protoPayload': {
                '@type': 'type.googleapis.com/google.appengine.logging.v1.RequestLog',
                'method': 'GET',
                'resource': '/test',
                'status': 200,
                'line': [
                    {
                        'time': '2024-01-01T12:00:00.100Z',
                        'severity': 'INFO',
                        'logMessage': 'Starting request'
                    },
                    {
                        'time': '2024-01-01T12:00:00.200Z',
                        'severity': 'ERROR',
                        'logMessage': 'Something went wrong'
                    }
                ]
            },
            'resource': {
                'type': 'gae_app',
                'labels': {
                    'module_id': 'default',
                    'version_id': 'v1'
                }
            },
            'trace': 'projects/test/traces/test123'
        }
        log = request_logs.RequestLog(entry)
        # Should be ERROR (highest severity from embedded logs)
        self.assertEqual(log.severity, 'ERROR')
        # Add some app logs
        app_log_entry = {
            'timestamp': '2024-01-01T12:00:00.150Z',
            'severity': 'CRITICAL',
            'textPayload': 'Critical error!'
        }
        log._append_logs([request_logs.LogMessage(entry=app_log_entry)])
        # Should now be CRITICAL
        self.assertEqual(log.severity, 'CRITICAL')

    def test_cursor_functionality(self):
        """Test Cursor encoding/decoding and usage."""
        # Create a cursor with all parameters
        cursor = request_logs.Cursor(
            max_age=timedelta(hours=2),
            service='backend',
            version='v1',
            min_severity='WARNING',
            path_filter='/api/*',
            status_filter='5xx',
            page_size=100
        )

        # Test encoding to URL-safe string
        encoded = cursor.urlsafe_string()
        self.assertIsInstance(encoded, str)
        self.assertNotIn('=', encoded)  # Should not have padding

        # Test decoding from URL-safe string
        decoded = request_logs.Cursor.from_urlsafe_string(encoded)
        # We can't directly compare timestamps since they depend on "now"
        self.assertIsNotNone(decoded._start_timestamp)
        self.assertEqual(decoded._service, 'backend')
        self.assertEqual(decoded._version, 'v1')
        self.assertEqual(decoded._min_severity, 'WARNING')
        self.assertEqual(decoded._path_filter, '/api/*')
        self.assertEqual(decoded._status_filter, '5xx')
        self.assertEqual(decoded._page_token, '')
        self.assertEqual(decoded._page_size, 100)

        # Test with_page_token method
        new_cursor = cursor.with_page_token('token456')
        self.assertEqual(new_cursor._page_token, 'token456')
        self.assertEqual(new_cursor._service, 'backend')
        # Original cursor should be unchanged
        self.assertEqual(cursor._page_token, '')

        # Test using cursor with fetch_logs
        logs, next_cursor = self.client.fetch_request_logs(cursor)
        self.assertIsNotNone(logs)
        self.assertIsNotNone(next_cursor)
        self.assertIsNotNone(next_cursor._start_timestamp)
        self.assertEqual(next_cursor._service, 'backend')
        self.assertEqual(next_cursor._version, 'v1')
        self.assertEqual(next_cursor._min_severity, 'WARNING')
        self.assertEqual(next_cursor._path_filter, '/api/*')
        self.assertEqual(next_cursor._status_filter, '5xx')
        self.assertEqual(next_cursor._page_token, 'token123')  # Next page token from API
        self.assertEqual(next_cursor._page_size, 100)

        # Test invalid cursor string
        with self.assertRaises(ValueError):
            request_logs.Cursor.from_urlsafe_string('invalid_cursor')


if __name__ == '__main__':
    unittest.main()