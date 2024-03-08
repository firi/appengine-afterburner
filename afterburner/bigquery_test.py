import unittest
import json
import datetime

from google.appengine.ext import testbed

from .bigquery import Client, Row, QueryTimeoutError
from .exceptions import RequestFailedError

# Test times that are used in the tests
_EXAMPLE_DATE = datetime.datetime(2024, 1, 1, 12)
_EXAMPLE_TIMESTAMP = _EXAMPLE_DATE.timestamp()


class BigQueryClientTest(unittest.TestCase):
    def setUp(self):
        self.testbed = testbed.Testbed()
        self.testbed.setup_env(app_id='afterburner')
        self.testbed.activate()
        self.testbed.init_memcache_stub()
        self.testbed.init_app_identity_stub()
        self.testbed.init_urlfetch_stub(urlmatchers=[
            _make_bigquery_urlmatcher(),
        ])

    def tearDown(self):
        self.testbed.deactivate()

    def test_client_construction(self):
        # Default constructed client should get the project id from the
        # app identity client.
        client = Client()
        self.assertEqual(client.project, "afterburner")
        # Manual project identifier
        self.assertEqual(Client(project="test").project, "test")

    def test_bigquery_insert(self):
        client = Client()
        rows = [
            {"name": "test", "age": 123, "time": _EXAMPLE_TIMESTAMP },
            {"name": "test2", "age": 999, "time": _EXAMPLE_TIMESTAMP }
        ]
        table = "dataset.table"
        client.insert_rows(table, rows)
        client.insert_rows(table, rows, row_ids=["id1", "id2"])
        single_row_with_none = [{"name": "test3", "age": None}]
        client.insert_rows(table, [single_row_with_none])

    def test_bigquery_insert_error(self):
        client = Client()
        # the error string will trigger the urlmatcher to return an error
        # response
        table = "dataset.error500"
        rows = [{"name": "test", "age": 123}]
        with self.assertRaises(RequestFailedError):
            client.insert_rows(table, rows)

    def test_bigquery_query(self):
        client = Client()
        results = client.query("SELECT * FROM `afterburner.dataset.table`")
        # These values match the data in the example response below.
        expected_values = [
            ["test1", 123, _EXAMPLE_DATE],
            ["test2", 456, _EXAMPLE_DATE],
            ["test3", None, None]
        ]
        self.assertEqual(len(results), len(expected_values))
        for row, expected_value in zip(results, expected_values):
            self.assertEqual(row.name, expected_value[0])
            self.assertEqual(row.age, expected_value[1])
            self.assertEqual(list(row), expected_value)

    def test_bigquery_query_timeout(self):
        client = Client()
        with self.assertRaises(QueryTimeoutError):
            client.query("SELECT * FROM `afterburner.dataset.timeout`")
        with self.assertRaises(RequestFailedError):
            client.query("SELECT * FROM `afterburner.dataset.timeout`")



class RowTest(unittest.TestCase):
    def test_row_access_by_field_name(self):
        row = Row(["name", "age"], ["test", 123])
        self.assertEqual(row.name,  "test")
        self.assertEqual(row.age, 123)

    def test_row_to_string(self):
        row = Row(["name", "age"], ["test", 123])
        self.assertEqual(str(row), "Row(name=test, age=123)")

    def test_row_items(self):
        # Test the items() function and ordering of values
        row = Row(["name", "age", "data"], ["test", 123, None])
        items = [("name", "test"), ("age", 123), ("data", None)]
        self.assertEqual(row.items(), items)
        self.assertEqual(list(row), [value for _, value in items])
        # Test the values() function
        self.assertEqual(list(row), row.values())


# An example response for a query() call to BigQuery. Contains a None field.
_QUERY_RESPONSE = {
    "kind": "bigquery#queryResponse",
    "schema": {
        "fields": [
            {
                "name": "name",
                "type": "STRING",
                "mode": "NULLABLE"
            },
            {
                "name": "age",
                "type": "INTEGER",
                "mode": "NULLABLE"
            },
            {
                "name": "time",
                "type": "TIMESTAMP",
                "mode": "NULLABLE"
            }
        ]
    },
    "jobReference": {
        "projectId": "afterburner",
        "jobId": "job12345"
    },
    "totalRows": "3",
    "rows": [
        {"f": [{"v": "test1"}, {"v": "123"}, {"v": f"{_EXAMPLE_TIMESTAMP}" }]},
        {"f": [{"v": "test2"}, {"v": "456"}, {"v": f"{_EXAMPLE_TIMESTAMP}" }]},
        {"f": [{"v": "test3"}, {}, {}]},  # Empty fields to indicate None
    ],
    "jobComplete": True,
}

# Response for a query that did not finish in time
_TIMEOUT_RESPONSE = {
    "kind": "bigquery#queryResponse",
    "schema": {
        "fields": [
            {
                "name": "name",
                "type": "STRING",
                "mode": "NULLABLE"
            },
            {
                "name": "age",
                "type": "INTEGER",
                "mode": "NULLABLE"
            },
            {
                "name": "time",
                "type": "TIMESTAMP",
                "mode": "NULLABLE"
            }
        ]
    },
    "jobReference": {
        "projectId": "afterburner",
        "jobId": "job12345"
    },
    "totalRows": "0",
    "rows": [],
    "jobComplete": False,
}


def _make_bigquery_urlmatcher():
    """
    Make an url fetcher pair to intercept the BigQuery API calls and return
    special responses depending on the input url and payload to test various
    scenarios.
    """
    def match_bigquery_url(url):
        return "https://bigquery.googleapis.com/bigquery/v2" in url

    def return_response(url, payload, method, headers, request, response, **kwargs):
        if "/insertAll" in url:
            if "error500" in url:
                response.StatusCode = 500
                response.Content = json.dumps({}).encode('utf-8')
            else:
                response.StatusCode = 200
                response.Content = json.dumps({}).encode('utf-8')
        elif "/queries" in url:
            if "timeout" in payload.decode('utf-8'):
                response.StatusCode = 200
                response.Content = json.dumps(_TIMEOUT_RESPONSE).encode('utf-8')
            else:
                response.StatusCode = 200
                response.Content = json.dumps(_QUERY_RESPONSE).encode('utf-8')

    return (match_bigquery_url, return_response)



if __name__ == '__main__':
    unittest.main()
