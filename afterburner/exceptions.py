"""
Custom exception classes that are thrown in the afterburner module
"""


class RequestFailedError(Exception):
    """
    Generic exception raised for remote API calls that fail in some way.

    Properties:
        http_status_code: An integer of the HTTP status code if available.
                If not set, this value is 0.
    """
    def __init__(self, http_status_code=None, message=None,
                exception=None):
        """
        Creates a new exception.

        Args:
            http_status_code: Optional HTTP status code for failed HTTP
                requests.
            message: Additional description of the error, if available.
            exception: Optional underlying exception that caused the request
                to fail.
        """
        if http_status_code is not None:
            self.http_status_code = http_status_code
            self.message = f"Request failed with http status code {http_status_code}"
            if message:
                self.message += f": {message}"
        else:
            self.http_status_code = 0
        if exception is not None:
            self.message = str(exception)
        super().__init__(self.message)

