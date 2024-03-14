"""
Example handlers to demo various features of Afterburner.
"""
import logging
from flask import Flask
import time

application = Flask(__name__)

@application.route('/log')
def log_multiple_lines():
    """
    Logs multiple lines. These logs can be correlated with the request
    by selecting "request_log" in the "correlate by" section of the log viewer.
    """
    logging.info("Info message")
    time.sleep(0.05)
    logging.warning("Warning message")
    time.sleep(0.05)
    logging.error("Error message")
    return "Logged some lines! Check the log viewer."


@application.route('/internal-error')
def log_exception():
    """
    Raises a exception in an request. This error is viewable in the error
    reporting section of GCP.
    """
    logging.warning("We are going to raise an exception")
    raise RuntimeError("An example error")




# Separate application for BigQuery client on the prefix /bigquery
bigquery_application = Flask("bigquery")

# Dataset identifier must be specified together with the table
_BQ_TABLE = "dataset_demo.table_demo"


@bigquery_application.route("/insert")
def bigquery_insert():
    """
    Example use of the BigQuery client for streaming inserts. Uses the
    default App Engine service account.
    """
    from afterburner.bigquery import Client
    row = { "name": "test", "age": 123, "time": time.time() }
    client = Client()
    client.insert_rows(_BQ_TABLE, [row])
    return "Inserted a row"


@bigquery_application.route("/query")
def bigquery_query():
    """
    Example use of the BigQuery client for queries. Uses the
    default App Engine service account to query a table in the same
    project.
    """
    from afterburner.bigquery import Client
    client = Client()
    results = client.query(f"SELECT name, age, time "
                           f"FROM `{client.project}.{_BQ_TABLE}` "
                           f"ORDER BY time DESC "
                           f"LIMIT 100")
    lines = []
    for row in results:
        lines.append(f"Name={row.name}, Age={row.age}")
    return "\n".join(lines)


# Wrapper function to create the main WSGI application. The application
# is created through a function, so it can also be used from unittests.
#
# This is needed because wrag_wsgi_app() copies the current environment
# variables 'into' the app, and those are important for certain tests. These
# must thus be set first before this function is called.
def create_appengine_app(enable_structured_logging=True):
    # The WSGICombiner class routes to different WSGI applications based on
    # the path prefix.
    from afterburner.wsgi import WSGICombiner
    app = WSGICombiner(application, {
        '/bigquery': bigquery_application,
    })
    # The StructuredLoggingMiddleware formats logs so that they can be
    # correlated with the requests in Cloud Logging.
    #
    # Only wrap on the production environment, as the structured logging
    # makes the output very spammy while testing.
    from afterburner.logging import StructuredLoggingMiddleware
    if enable_structured_logging:
        app = StructuredLoggingMiddleware(app, level=logging.INFO)

    # Enable the App Engine bundled services for Python 3
    from google.appengine.api import wrap_wsgi_app
    app = wrap_wsgi_app(app)

    return app


# Default entry point of an App Engine app.
app = create_appengine_app()

