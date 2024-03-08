import unittest
from google.appengine.ext import testbed
from afterburner import bigquery_test


class MainTest(unittest.TestCase):
    def setUp(self):
        self.testbed = testbed.Testbed()
        self.testbed.setup_env(app_id='afterburner')
        self.testbed.activate()
        self.testbed.init_memcache_stub()
        self.testbed.init_app_identity_stub()
        self.testbed.init_urlfetch_stub(urlmatchers=[
            bigquery_test._make_bigquery_urlmatcher()
        ])

        from main import create_appengine_app
        # Disable structured logging middleware for tests as it is very
        # spammy.
        self.app = create_appengine_app(enable_structured_logging=False)
        # Directly create a test client as the Flask app is wrappped in
        # middleware.
        from werkzeug.test import Client
        from werkzeug.wrappers import Response
        self.client = Client(self.app, Response)

    def tearDown(self):
        self.testbed.deactivate()

    def test_log(self):
        response = self.client.get('/log')
        self.assertEqual(response.status_code, 200)

    def test_internal_error(self):
        response = self.client.get('/internal-error')
        self.assertEqual(response.status_code, 500)

    def test_bigquery_insert(self):
        response = self.client.get('/bigquery/insert')
        self.assertEqual(response.status_code, 200)

    def test_bigquery_query(self):
        response = self.client.get('/bigquery/query')
        self.assertEqual(response.status_code, 200)



if __name__ == '__main__':
    unittest.main()
