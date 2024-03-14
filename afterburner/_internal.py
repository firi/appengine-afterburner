"""
Internal functions and classes for the Afterburner implementation.
"""
import time
import json
from google.appengine.api import app_identity
from google.appengine.api import memcache
from google.appengine.api import urlfetch
from google.appengine.api import urlfetch_errors

from .exceptions import RequestFailedError


def get_project_id() -> str:
    """
    Returns the App Engine project identifier
    """
    return app_identity.get_application_id()


def call_google_api(url,
                    data=None,
                    method="POST",
                    timeout=None,
                    scope=None,
                    project=None,
                    service_account_id=None):
    """
    Perform a REST request to a Google APIs REST endpoint.

    Args:
        url: The url to request.
        method: The HTTP request method.
        data: A JSON-encodable item that is send as payload with the request.
        timeout: The timeout in seconds of the request.
        scope: The scope required for the API that is called.
        project: The project identifier that will be billed for the request, if
            required.
        service_account_id: Optional identifier of the service account that will
            make the request. If not set, the default App Engine service account
            is used.

    Returns:
        The decoded JSON response of the request. Some requests do not return
        any content (for example with a 204 status), and in that case None is
        returned.

    Raises:
        RequestFailedError: If the request could not be completed or some
            reason. This can be a network error or an error reported by the
            API.
    """
    if not project:
        raise ValueError("Must provide a project")
    if not scope:
        raise ValueError("A scope must be provided")

    token = _get_access_token(scope, service_account_id=service_account_id)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Goog-User-Project": project,
        "Content-Type": "application/json"
    }
    try:
        response = urlfetch.fetch(url=url,
                                  payload=json.dumps(data),
                                  method=method,
                                  deadline=timeout,
                                  headers=headers)
        status = response.status_code
        if (status // 100) != 2:
            raise RequestFailedError(http_status_code=status,
                                     message=_get_error_message(response.content))
        if status in (204, 205):
            return None
        return json.loads(response.content)
    except urlfetch_errors.Error as e:
        raise RequestFailedError(exception=e)


# Namespace so we do not accidentally interfere with other items stored in
# memcache.
_MEMCACHE_NAMESPACE = '_afterburner'
# A margin of 5 minutes so we don't hit too close to the expiration date with
# the tokens.
_TOKEN_EXPIRY_MARGIN = 300

# In-memory cache of access tokens and the expiration time. Dictionary
# operations are threadsafe in Python, so that is sufficient for our use case.
_access_token_cache = {}


def _get_access_token(scope, service_account_id=None):
    """
    An implementation to access app_identity.get_access_token(), but the token
    is cached in instance memory and memcache, as retrieving tokens from the
    metadata server is not as fast as we want.

    Args:
      scope: The requested API scope string.
      service_account_id: An optional service account identifier. If not
        provided, uses the default App Engine service account.

    Returns:
        A string access token.
    """
    if service_account_id:
        cache_key = f'token-{scope}-{service_account_id}'
    else:
        cache_key = f'token-{scope}'

    # Try to grab the token first from instance memory
    cached = _access_token_cache.get(cache_key)
    if cached is not None:
        access_token, expires = cached
        expires_with_margin = expires - _TOKEN_EXPIRY_MARGIN
        if time.time() < expires_with_margin:
            return access_token
    # If not in memory, try memcache
    memcache_value = memcache.get(cache_key, namespace=_MEMCACHE_NAMESPACE)
    if memcache_value:
        access_token, expires = memcache_value
    else:
        access_token, expires = app_identity.get_access_token(
            scope, service_account_id=service_account_id)
        memcache_expires = expires - _TOKEN_EXPIRY_MARGIN
        memcache.add(cache_key, (access_token, expires),
                     memcache_expires,
                     namespace=_MEMCACHE_NAMESPACE)
    _access_token_cache[cache_key] = (access_token, expires)
    return access_token


def _get_error_message(response):
    """
    Tries to decode the JSON response and find an error message.

    Returns:
        A string error message, or None if no error could be found, or the
        response could not be decoded.
    """
    try:
        return json.loads(response).get("error", {}).get("message")
    except (ValueError, TypeError):
        return None
