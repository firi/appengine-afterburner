"""
A very basic BigQuery client for App Engine, without any additional
dependencies besides the appengine builtin APIs.

This client can streaming insert new data into BigQuery tables and can
be used for basic quering. To authenticate, the default App Engine service
account is used. The BigQuery project is the same as the App Engine project
by default.

The client uses the App Engine urlfetch API to make requests. This gives
automatic Cloud Trace support and allows for testing using the appengine
testbed API and the provided urlmatchers in this module.

Usage:
    from afterburner.bigquery import Client

    client = Client()
    row = {
        "name": "test",
        "age": 123,
    }
    client.insert_rows("dataset_id.table_id", [row])

    result = client.query("SELECT * FROM `project.dataset.table`")
    for row in result:
        print(f"Name: {row.name}, Age: {row.age}")
        values = list(row)
"""
from typing import List
from datetime import datetime

from ._internal import get_project_id, call_google_api
from .exceptions import RequestFailedError

class QueryTimeoutError(RequestFailedError):
    """
    Exception raised when the Client.query() method cannot complete in time.
    """


class Client:
    """
    A BigQuery client that uses the App Engine credentials of the default
    service account.

    Properties:
        project: The application project name.
    """
    def __init__(self, project: str=None, service_account_id: str=None):
        """
        Creates a new client:

        Args:
            project: An optional string identifier of the project to which
                the requests are directed. If not set, the App Engine project
                identifier is used.
            service_account_id: An optional identifier for the service account
                to use. If None, the default App Engine service account is used.
        """
        if project is None:
            project = get_project_id()
        if not project or not isinstance(project, str):
            raise ValueError("project must be a non-empty string")
        self.project = project
        self._service_account_id = service_account_id
        self._scope = "https://www.googleapis.com/auth/bigquery"


    def insert_rows(self, dataset_and_table: str, rows, row_ids=None):
        """
        Insert one or more rows into a BigQuery table.

        Args:
            dataset_and_table: The dataset and table identifier. This identifier
                must contain both the dataset and table names separated by a
                dot. For example "dataset_name.table_name".
            rows: A list of one or more dictionaries. Each field in the
                dictionary must be a field in the table. The value must be
                a valid JSON-encodable value for the type of the field.
            rows_ids: An optional list of insertIds to help prevent duplication.
                If provided, there must be exactly one row_id for each row of
                type string.

        Returns:
            A list with errors that have occurred. Each error is a dictionary
            with an 'index' that specifies the row with the error. An "errors"
            entry in the dictionary has more information about the error. If no
            errors have occurred, the returned list is empty.

        Raises:
            HTTPError: If the request failed. This is not raised on data
                insertion failures. For that, examine the returned list of
                errors.
        """
        dataset, table = dataset_and_table.split(".")
        if not dataset or not table:
            raise ValueError("Invalid dataset and table identifier.")
        if row_ids and len(row_ids) != len(rows):
            raise ValueError("Must specify exactly one row_id for each row")

        url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{self.project}/datasets/{dataset}/tables/{table}/insertAll"
        data = [{ "json": row } for row in rows]
        if row_ids:
            for row_data, row_id in zip(data, row_ids):
                row_data["insertId"] = row_id

        response = call_google_api(url, data={ "rows": data},
                                   project=self.project,
                                   scope=self._scope,
                                   service_account_id=self._service_account_id)
        return response.get('insertErrors', [])



    def query(self, query, legacy_sql=False, query_timeout=None, max_results=1000):
        """
        Run a query, wait for it to finish, then return the result. The entire
        query results are returned in a single request and in memory, so make
        sure the queries have a limited result set.

        Args:
            query: A complete BigQuery query string.
            legacy_sql: Set to true if the query uses legacy SQL.
            query_timeout: The timeout in seconds in which the query must
                complete.
            max_results: The maximum number of rows that are returned from the
                query, if the result set is larger than this value. If set to
                None, no maximum is applied, but the response sizes are still
                limited by service and underlying HTTP transport.

        Returns:
            A list of Row objects that are the result of the query.

        Raises:
            RequestFailedError: If the request failed or the query was invalid.
            QueryTimeout: When the query could not complete within the time
                specified.
        """
        result = self._raw_query(query, legacy_sql=legacy_sql,
                                 query_timeout=query_timeout,
                                 max_results=max_results)
        complete = result.get('jobComplete', False)
        if not complete:
            raise QueryTimeoutError("Query did not complete in time")
        return _convert_response_to_rows(result)


    def _raw_query(self, query, legacy_sql=False, query_timeout=None,
                   max_results=1000):
        """
        As the query() function, but returns the entire (decoded) JSON
        response.

        Args:
            query: A complete BigQuery query string.
            legacy_sql: Set to true if the query uses legacy SQL.
            query_timeout: The timeout in seconds in which the query must complete.
            max_results: The maximum number of rows that are returned.

        Returns:
            A dictionary with the response from the BigQuery API. Note that
            the result might not be complete. This must be checked manually.

        Raises:
            RequestFailedError: If the request failed or the query was invalid.
        """
        url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{self.project}/queries"
        data = {
            "query": query,
            "useLegacySql": legacy_sql
        }
        request_timeout = None
        if query_timeout is not None:
            data["timeoutMs"] = int(query_timeout * 1000)
            request_timeout = float(query_timeout + 2)  # extra slack
        if max_results is not None and max_results >= 1:
            data["maxResults"] = int(max_results)
        return call_google_api(url, data=data,
                               timeout=request_timeout,
                               project=self.project,
                               scope=self._scope,
                               service_account_id=self._service_account_id)


class Row:
    """
    Data of a single row in a BigQuery query result. The data in the row can
    be accessed through the field name. A row can also be converted to a list
    of its values.
    """
    def __init__(self, field_names, values):
        """
        Create a new Row to store a query result. The data in the values will
        be converted to the appropriate Python object.

        Args:
            field_names: A list of strings of the fields in a row, in order
            values: A list of values, one for each field. If a field has
                no value, None must be specified.
        """
        if len(field_names) != len(values):
            raise ValueError("field_names and values must be the same size")
        # Data is stored in a single dict and makes use of the builtin ordering
        # available in Python 3.7+.
        self._data = dict(zip(field_names, values))

    def items(self):
        """
        Returns an list of tuples (field name, value) that make up this row.
        """
        return list(self._data.items())

    def values(self):
        """
        Returns a list with all values in this row.
        """
        return list(self)

    def __getattr__(self, name):
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(f"'Row' object has no field '{name}'")

    def __iter__(self):
        return iter(self._data.values())

    def __len__(self):
        return len(self._data)

    def __repr__(self):
        field_value_pairs = []
        for field, value in self._data.items():
            field_value_pairs.append(f"{field}={value}")
        return f"Row({', '.join(field_value_pairs)})"


def _convert_response_to_rows(response_data) -> List[Row]:
    """
    Extracts the data from the big query |response| as native Python data.

    Returns the result as a list of tuples, if each row contains more
    than one field. Otherwise, a list of elements is returned.

    The returned values are converted to their proper types.
    """
    field_names = [field['name'] for field
                   in response_data['schema']['fields']]
    field_types = {field['name']: field['type'] for field
                   in response_data['schema']['fields']}

    # Functiont to convert BigQuery string results to their Python types
    def coerce_value(value, type):
        if value is None:
            return None
        elif type == 'STRING':
            return value
        elif type == 'INTEGER':
            return int(value)
        elif type == 'FLOAT' or type == 'FLOAT64':
            return float(value)
        elif type == 'BOOLEAN':
            return value.lower() == 'true'
        elif type == 'TIMESTAMP':
            return datetime.fromtimestamp(float(value))
        elif type == 'DATE':
            return datetime.strptime(value, "%Y-%m-%d")

        # TOOD(tijmen): Add more types
        raise ValueError(f"Unsupported type '{type}' in query result")

    # Convert each row in the response to a Row object
    rows = []
    for row_data in response_data['rows']:
        values = []
        for field_data, field_name in zip(row_data['f'], field_names):
            field_type = field_types[field_name]
            coerced_value = coerce_value(field_data.get('v'), field_type)
            values.append(coerced_value)
        rows.append(Row(field_names, values))
    return rows
