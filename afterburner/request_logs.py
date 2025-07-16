"""
Client class for fetching App Engine request logs via Cloud Logging API. This
client automatically merges request and application logs into a single stream
of RequestLog objects, to reproduce the Classic App Engine logs experience. These
request logs require the afterburner.StructuredLoggingMiddleware being used
to handle logging.

Usage:
    from afterburner.request_logs import Client, Cursor
    from datetime import datetime, timedelta

    client = Client()

    # Create a cursor with search parameters
    cursor = Cursor(
        max_age=timedelta(hours=1),  # Show logs from the last hour
        service='default',
        min_severity='WARNING',
        status_filter='5xx'
    )
    # Then fetch logs using the cursor
    logs, next_cursor = client.fetch_request_logs(cursor)

    # Process the results
    for log in logs:
        print(f"{log.timestamp}: {log.method} {log.resource} -> {log.status}")
        for msg in log.logs:
            print(f"  {msg.severity}: {msg.message}")

    # Continue fetching if there are more results
    if next_cursor:
        more_logs, final_cursor = client.fetch_request_logs(next_cursor)

    # Cursors can be serialized for URLs or storage
    cursor_string = cursor.urlsafe_string()
    restored_cursor = Cursor.from_urlsafe_string(cursor_string)
"""
import json
import base64
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from urllib.parse import urlparse
from afterburner._internal import call_google_api, get_project_id


class RequestLog:
    """Represents a single request log entry.

    This class encapsulates a request log from Google Cloud Logging, including
    the HTTP request details and any associated application logs.

    Attributes:
        project_id: The Google Cloud project ID string, used for generating
            trace viewer URLs and other project-specific operations.
        timestamp: A datetime object representing when the request was received
            by the App Engine server.
        method: The HTTP method string such as GET, POST, PUT, DELETE, etc.
        resource: The requested URL path string, for example '/api/users/123'.
        status: An integer HTTP response status code like 200, 404, 500, etc.
        latency_seconds: A float representing the total request processing time
            in seconds, from when the request was received to when the response
            was sent.
        request_size: An integer representing the size of the HTTP request body
            in bytes.
        response_size: An integer representing the size of the HTTP response body
            in bytes.
        user_agent: The User-Agent header string from the request, identifying
            the client browser or application.
        remote_ip: The IP address string of the client that made the request.
        service: The App Engine service name string, defaulting to 'default' if
            not specified. Services allow you to deploy multiple components of
            your application.
        version: The App Engine version ID string. Each deployment creates a new
            version within a service.
        trace_id: A string identifier used to correlate this request with its
            associated application logs. All logs generated during request
            processing share the same trace ID.
        trace_sampled: A boolean to indicate if this trace ID is sampled in Cloud
            trace. Most traces are not sampled.
        logs: A list of LogMessage objects containing all log messages associated
            with this request. This includes both application-generated logs (
            correlated using the trace ID) and system-generated embedded logs
            from the request itself.
        severity: The highest severity level string found among all logs.
            Will be None if there are no logs, or one of DEBUG, INFO, WARNING,
            ERROR, or CRITICAL representing the most severe log level encountered.
        is_synthetic: A boolean indicating if this is a synthetic request log
            created for orphaned application logs that had no corresponding
            request log. This can happen if log sinks are active that discard
            these request logs but keep application logs. Synthetic logs
            generally do not have complete request data.
    """
    def __init__(self, entry: dict,
                 logs: list['LogMessage']=None,
                 is_synthetic=False,):
        """
        Creates a new RequestLog from a Cloud Logging Api entry, with the
        given |logs| attached to it.
        """
        if logs is None:
            logs = []
        self.timestamp = _parse_timestamp(entry.get('timestamp', ''))
        # Request fields
        proto = entry.get('protoPayload', {})
        self.method = proto.get('method', '')
        self.resource = proto.get('resource', '')
        self.status = proto.get('status', 0)
        self.latency_seconds = _parse_latency(proto.get('latency', '0s'))
        self.request_size = proto.get('requestSize', 0)
        self.response_size = proto.get('responseSize', 0)
        self.user_agent = proto.get('userAgent', '')
        self.remote_ip = proto.get('ip', '')
        # Resource labels
        labels = entry.get('resource', {}).get('labels', {})
        self.project_id = labels.get('project_id', '')
        self.service = labels.get('module_id', 'default')
        self.version = labels.get('version_id', '')
        # Trace id data
        self.trace_id = _extract_trace_id(entry.get('trace', ''))
        self.trace_sampled = entry.get("traceSampled", False)
        self.logs = []
        self.severity = None
        # Initialize logs list with embedded logs from protoPayload.line
        lines = proto.get('line', [])
        self.logs.extend([LogMessage(line_entry=line) for line in lines])
        self.is_synthetic = is_synthetic
        # Append all normal log message
        self.logs.extend(logs)
        self.logs.sort(key=lambda log: log.timestamp)
        self._calculate_severity()


    def _calculate_severity(self):
        """Calculate and set the highest severity from all logs."""
        max_severity, max_level = None, 0
        for log in self.logs:
            level = _SEVERITY_ORDER.get(log.severity, 0)
            if level > max_level:
                max_level = level
                max_severity = log.severity
        self.severity = max_severity


class LogMessage:
    """Represents a single log message, either from application code or system-generated.

    This class represents both application logs (generated by user code during
    request processing) and embedded logs (system-generated logs that were part
    of the request log in classic App Engine).

    Attributes:
        timestamp: A datetime object indicating when this log message was generated.
        message: The log message text string.
        severity: A string representing the log level, typically one of DEBUG,
            INFO, WARNING, ERROR, or CRITICAL.
        file: A string containing the source file path where this log statement
            was executed (empty for system logs).
        line: An integer line number within the source file (0 for system logs).
        function: A string containing the name of the function or method that
            generated this log message (empty for system logs).
        is_embedded: A boolean indicating if this is a system-generated log that
            was embedded in the request log. Embedded logs are from Classic App
            Engine where they were attached to request logs. They are still
            output for some requests, such as warmup requests.
    """
    def __init__(self, entry: dict = None, line_entry: dict = None):
        """Initialize from either a Cloud Logging API entry or embedded line entry.

        Args:
            entry: A log entry from Cloud Logging API (for application logs)
            line_entry: A line entry from protoPayload.line (for embedded logs)
        """
        if entry:
            # This is an application log from Cloud Logging
            self.timestamp = _parse_timestamp(entry.get('timestamp', ''))
            # Extract message and severity
            self.message = entry.get('textPayload', '') or entry.get('jsonPayload', {}).get('message', '')
            self.severity = entry.get('severity', 'INFO')
            # Extract source location
            source = entry.get('sourceLocation', {})
            self.file = source.get('file', '')
            self.line = source.get('line', 0)
            self.function = source.get('function', '')
            self.is_embedded = False
        elif line_entry:
            # This is an embedded log from protoPayload.line
            self.timestamp = _parse_timestamp(line_entry.get('time', ''))
            self.severity = line_entry.get('severity', 'INFO')
            self.message = line_entry.get('logMessage', '')
            # System-generated logs don't have source location
            self.file = ''
            self.line = 0
            self.function = ''
            self.is_embedded = True
        else:
            raise ValueError("Either entry or line_entry must be provided")


class Cursor:
    """
    Encapsulates all parameters needed to fetch logs, including pagination state.

    This cursor can be serialized to a URL-safe string and reconstructed, making
    it easy to implement pagination and resumption of log fetching.
    """
    def __init__(self, max_age: timedelta = None,
                 service: str = '', version: str = '',
                 min_severity: str = '', status_filter: str = '',
                 path_filter: str = '',  page_size: int = 200,
                 _page_token: str = '', _start_timestamp: str = None):
        """Initialize a cursor for a fetch_request_logs call.

        Args:
            max_age: How far back to look for logs (e.g., timedelta(hours=1))
            service: Filter by App Engine service name
            version: Filter by App Engine version
            min_severity: Minimum severity level for logs. Valid values are
                'DEBUG', 'INFO', 'WARNING', 'ERROR' and 'CRITICAL' or an
                empty string for no filter.
            path_filter: Filter by request paths (supports wildcards)
            status_filter: Filter by status code. Valid values are '2xx', '3xx',
                '4xx', '5xx' and 'errors' for both 4xx and 5xx statuses.
            page_size: Number of entries to fetch per page
            _page_token: Internal token for pagination
            _start_timestamp: Internal timestamp (used for pagination)
        """
        # Validate input arguments
        if _start_timestamp:
            # This is for internal use (pagination, from_urlsafe_string)
            start_timestamp = _start_timestamp
        elif max_age:
            if not isinstance(max_age, timedelta):
                raise ValueError("max_age must be a timedelta object")
            start_time = datetime.now(timezone.utc) - max_age
            # Format as RFC3339 with Z suffix, without microseconds for cleaner
            # timestamps
            start_timestamp = start_time.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        else:
            raise ValueError("max_age is required and cannot be None")
        if service and not isinstance(service, str):
            raise ValueError(f"service must be a string, got {type(service).__name__}")
        if version and not isinstance(version, str):
            raise ValueError(f"version must be a string, got {type(version).__name__}")
        valid_severities = ['', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if min_severity not in valid_severities:
            raise ValueError(f"min_severity must be one of {valid_severities}, got '{min_severity}'")
        valid_status_filters = ['', '2xx', '3xx', '4xx', '5xx', 'errors']
        if status_filter not in valid_status_filters:
            raise ValueError(f"status_filter must be one of {valid_status_filters}, got '{status_filter}'")
        if not isinstance(page_size, int) or page_size < 1:
            raise ValueError(f"page_size must be a positive integer, got {page_size}")
        if page_size > 1000:
            raise ValueError(f"page_size cannot exceed 1000, got {page_size}")

        self._start_timestamp = start_timestamp
        self._service = service
        self._version = version
        self._min_severity = min_severity
        self._path_filter = path_filter
        self._status_filter = status_filter
        self._page_token = _page_token
        self._page_size = page_size


    def urlsafe_string(self) -> str:
        """
        Encode the cursor to a URL-safe string that can be used to recreate
        the cursor with Cursor.from_urlsafe_string().
        """
        data = {
            'ts': self._start_timestamp,
            'svc': self._service,
            'ver': self._version,
            'sev': self._min_severity,
            'path': self._path_filter,
            'stat': self._status_filter,
            'tok': self._page_token,
            'sz': self._page_size
        }
        json_str = json.dumps(data, separators=(',', ':'))
        return base64.urlsafe_b64encode(json_str.encode('utf-8')) \
            .decode('ascii').rstrip('=')


    @staticmethod
    def from_urlsafe_string(urlsafe_str: str) -> 'Cursor':
        """
        Decode a cursor from a URL-safe string. The input argument must be
        a string produced by urlsafe_string().

        Raises:
            ValueError: If the string cannot be decoded or is invalid.
        """
        try:
            # Add padding if needed
            padding = 4 - (len(urlsafe_str) % 4)
            if padding != 4:
                urlsafe_str += '=' * padding
            json_str = base64.urlsafe_b64decode(urlsafe_str).decode('utf-8')
            data = json.loads(json_str)
            return Cursor(
                _start_timestamp=data['ts'],
                _page_token=data.get('tok', ''),
                service=data.get('svc', ''),
                version=data.get('ver', ''),
                min_severity=data.get('sev', ''),
                path_filter=data.get('path', ''),
                status_filter=data.get('stat', ''),
                page_size=data.get('sz', 200)
            )
        except Exception as e:
            raise ValueError(f"Invalid cursor string: {e}")

    def with_page_token(self, page_token: str) -> 'Cursor':
        """
        Create a new cursor with an updated page token.
        """
        return Cursor(
            _start_timestamp=self._start_timestamp,
            _page_token=page_token,
            service=self._service,
            version=self._version,
            min_severity=self._min_severity,
            path_filter=self._path_filter,
            status_filter=self._status_filter,
            page_size=self._page_size
        )


class Client:
    """
    Client for fetching App Engine logs from Cloud Logging API.
    """
    def __init__(self, project: str = None, service_account_id: str = None):
        """
        Creates a new request logs client.

        Args:
            project: An optional string identifier of the project to fetch logs from.
                If not set, the App Engine project identifier is used.
            service_account_id: An optional identifier for the service account
                to use. If None, the default App Engine service account is used.

        Raises:
            ValueError: If project is not a valid non-empty string or if
                service_account_id is provided but not a string.
        """
        if project is None:
            project = get_project_id()
        if not project or not isinstance(project, str):
            raise ValueError("project must be a non-empty string")
        self.project = project
        self._service_account_id = service_account_id
        self._scope = "https://www.googleapis.com/auth/logging.read"

    def fetch_request_logs(self, cursor: Cursor) -> tuple[list[RequestLog], Cursor | None]:
        """
        Fetch both request logs and application logs from Cloud Logging API.

        This fetches both request logs and application logs in a single query,
        then correlates them by trace ID.

        Args:
            cursor: A Cursor object containing all parameters for the fetch operation,
                including start timestamp, filters, and pagination state.

        Returns:
            Tuple of (logs, next_cursor) where:
            - logs: List of RequestLog objects with correlated app logs. Note
                that it is possible that this list is empty, but a next cursor
                is available. In that case, keep fetching more logs using
                the cursor to get to the results.
            - next_cursor: Cursor for fetching next page, or None if no more pages.
        """
        start_timestamp = cursor._start_timestamp
        service = cursor._service
        version = cursor._version
        min_severity = cursor._min_severity
        path_filter = cursor._path_filter
        status_filter = cursor._status_filter
        page_token = cursor._page_token
        page_size = cursor._page_size
        # Build query filter to get BOTH request logs and app logs
        filters = [
            'resource.type="gae_app"',
            f'timestamp>="{start_timestamp}"'
        ]
        if service:
            filters.append(f'resource.labels.module_id="{service}"')
        if version:
            filters.append(f'resource.labels.version_id="{version}"')

        # Build request-specific filters for the status code of requests
        request_filters = []
        if status_filter:
            if status_filter == '2xx':
                request_filters.append('(protoPayload.status>=200 AND protoPayload.status<300)')
            elif status_filter == '3xx':
                request_filters.append('(protoPayload.status>=300 AND protoPayload.status<400)')
            elif status_filter == '4xx':
                request_filters.append('(protoPayload.status>=400 AND protoPayload.status<500)')
            elif status_filter == '5xx':
                request_filters.append('(protoPayload.status>=500 AND protoPayload.status<600)')
            elif status_filter == 'errors':
                request_filters.append('(protoPayload.status>=400)')
        if path_filter:
            # Simple escape for the path filter - replace wildcards with regex equivalent
            # and escape special regex characters manually (except *)
            escaped = path_filter
            for char in '.+?^${}[]|()\\':
                escaped = escaped.replace(char, '\\' + char)
            # Convert * wildcards to .* regex
            escaped = escaped.replace('*', '.*')
            request_filters.append(f'(protoPayload.resource=~"{escaped}")')
        # Build the complete filter
        request_log_filter = 'protoPayload.@type="type.googleapis.com/google.appengine.logging.v1.RequestLog"'
        if request_filters:
            request_log_filter = f'({request_log_filter} AND {" AND ".join(request_filters)})'
        # App log filter are not request logs but potentially have a minimum severity.
        app_log_filter = 'NOT protoPayload.@type="type.googleapis.com/google.appengine.logging.v1.RequestLog"'
        if min_severity:
            app_log_filter = f'({app_log_filter} AND severity>="{min_severity}")'
        # OR filters to get both types
        filters.append(f'({request_log_filter} OR {app_log_filter})')
        filter_str = ' AND '.join(filters)
        # Make the request
        request_body = {
            "resourceNames": [f"projects/{self.project}"],
            "filter": filter_str,
            "orderBy": "timestamp desc",
            "pageSize": page_size
        }
        if page_token:
            request_body["pageToken"] = page_token
        response = call_google_api(
            url="https://logging.googleapis.com/v2/entries:list",
            method="POST",
            data=request_body,
            scope=self._scope,
            project=self.project,
            service_account_id=self._service_account_id
        )
        # Process response.
        #
        # First extract all application logs and group them by their trace
        # ID. Entries without a trace id are discarded as we cannot do anything
        # with them.
        entries = response.get('entries', [])
        app_logs_by_trace = defaultdict(list)
        for entry in entries:
            if entry.get('protoPayload'):
                continue
            trace_id = _extract_trace_id(entry.get('trace', ''))
            if trace_id:
                app_logs_by_trace[trace_id].append(entry)
        # Parse request logs and add the application logs to each request,
        # removin gthem from the dictionary in the process.
        request_logs: list[RequestLog] = []
        for entry in entries:
            proto_type = entry.get('protoPayload', {}).get('@type', '')
            if proto_type == 'type.googleapis.com/google.appengine.logging.v1.RequestLog':
                trace_id = _extract_trace_id(entry.get('trace', ''))
                logs = app_logs_by_trace.pop(trace_id, [])
                request_logs.append(RequestLog(entry, logs=[LogMessage(l) for l in logs]))
        # Then, for all remaining app logs without any request, we create
        # synthetic requests. Note that when we are filtering on HTTP status
        # code, we all of a sudden get a ton more of these, because the
        # application logs itself are not filtered on status! This could be
        # appended to the query,
        for logs in app_logs_by_trace.values():
            if status_filter and not _matches_status_filter(logs, status_filter):
                continue
            request_logs.append(_create_synthetic_request_log(logs))
        # Filter all requests that do not have the minimum severity, if we are
        # filtering on severity.
        if min_severity:
            value = _SEVERITY_ORDER.get(min_severity, 0)
            request_logs = [log for log in request_logs
                             if _SEVERITY_ORDER.get(log.severity, 0) >= value]
        # Because we might have added synthetic request logs, we need to sort
        # again on timestamp
        request_logs.sort(key=lambda x: x.timestamp, reverse=True)
        # Create cursor for continuation, if possible.
        next_cursor = None
        next_page_token = response.get('nextPageToken')
        if next_page_token:
            next_cursor = cursor.with_page_token(next_page_token)
        return request_logs, next_cursor


def _parse_timestamp(timestamp_str: str) -> datetime:
    """Parse RFC3339 timestamp to datetime object."""
    if not timestamp_str:
        raise ValueError("Cannot parse empty timestamp string")
    # Remove timezone suffix for simplicity
    if timestamp_str.endswith('Z'):
        timestamp_str = timestamp_str[:-1]
    try:
        return datetime.fromisoformat(timestamp_str)
    except:
        raise ValueError(f"Error parsing timestamp {timestamp_str}")

def _parse_latency(latency_str: str) -> float:
    """Parse latency string like '0.123s' to seconds as float."""
    if not latency_str:
        return 0.0
    try:
        return float(latency_str.rstrip('s'))
    except:
        return 0.0

def _extract_trace_id(trace: str) -> str:
    """
    Extract trace ID from a full trace entry. Usually in the
    form of projects/<projectname>/trace/<traceid>.
    """
    parts = trace.split('/')
    if len(parts) >= 4:
        return parts[-1]
    return ''

def _create_synthetic_request_log(orphaned_logs: list[dict]) -> RequestLog:
    """
    Create a synthetic RequestLog for orphaned application logs. In normal
    circumstances, there should always be a request log for logs recorded by
    our logging middleware. However, with Cloud Logging Log Sinks, it is easy
    to discard the request but only keep the application logs. In those cases,
    we still want to show the application logs, and thus we have to create
    a synthetic entry.

    Args:
        orphaned_logs: List of Cloud Logging data objects that each are
            application logs entries. They all must have the same trace_id.
    """
    if not orphaned_logs:
        raise ValueError("Must have at least one log")
    # Grab the trace
    trace = orphaned_logs[0].get('trace')
    trace_sampled = orphaned_logs[0].get('traceSampled')
    # Find the earliest timestamp
    earliest_timestamp = min(_parse_timestamp(log.get('timestamp')) for log in orphaned_logs)
    # We assume these logs come from afterburner logging, which have the
    # httpRequest data in every log.
    http_request = orphaned_logs[0].get('httpRequest', {})
    status = http_request.get('status', 0)
    method = http_request.get('requestMethod', 'UNKNOWN')
    resource = http_request.get('requestUrl', '')
    # Extract just the path from the URL if it's a full URL
    if resource and resource.startswith('http'):
        resource = urlparse(resource).path
    user_agent = http_request.get('userAgent', '')
    remote_ip = http_request.get('remoteIp', '')
    # Extract project and service info from the first log
    labels = orphaned_logs[0].get('resource', {}).get('labels', {})
    project_id = labels.get('project_id', '')
    service = labels.get('module_id', 'default')
    version = labels.get('version_id', '')
    # Create a synthetic entry that looks like a request log
    synthetic_entry = {
        'timestamp': earliest_timestamp.isoformat() + 'Z',
        'protoPayload': {
            '@type': 'type.googleapis.com/google.appengine.logging.v1.RequestLog',
            'method': method,
            'resource': resource,
            'status': status,
            'latency': '0s',
            'requestSize': '0',
            'responseSize': '0',
            'userAgent': user_agent,
            'ip': remote_ip,
        },
        'resource': {
            'type': 'gae_app',
            'labels': {
                'project_id': project_id,
                'module_id': service,
                'version_id': version
            }
        },
        'trace': trace,
        'traceSampled': trace_sampled,
    }
    return RequestLog(synthetic_entry,
                      logs=[LogMessage(log) for log in orphaned_logs],
                      is_synthetic=True)


# Severity levels in order of importance
_SEVERITY_ORDER = {
    'DEBUG': 1,
    'INFO': 2,
    'WARNING': 3,
    'ERROR': 4,
    'CRITICAL': 5
}

def _matches_status_filter(logs: list[dict], status_filter: str) -> bool:
    """
    Check if the application logs matches the given status filter. Returns
    True the first log matches the filter, False otherwise
    """
    status = logs[0].get('httpRequest', {}).get('status', 0)
    if status_filter == '2xx':
        return 200 <= status < 300
    elif status_filter == '3xx':
        return 300 <= status < 400
    elif status_filter == '4xx':
        return 400 <= status < 500
    elif status_filter == '5xx':
        return 500 <= status < 600
    elif status_filter == 'errors':
        return status >= 400
    return True
