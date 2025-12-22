"""
WSGI middleware wrapper to fix httpbin's bytearray response issue.

The httpbin /bytes endpoint returns bytearray, but gunicorn's async workers
(eventlet, gevent) expect bytes. This middleware converts bytearray to bytes.
"""
from httpbin import app as httpbin_app


class BytearrayFixMiddleware:
    """WSGI middleware that converts bytearray responses to bytes."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        response = self.app(environ, start_response)
        # Convert any bytearray items to bytes
        for item in response:
            if isinstance(item, bytearray):
                yield bytes(item)
            else:
                yield item


# Wrap the httpbin app with our middleware
app = BytearrayFixMiddleware(httpbin_app)
