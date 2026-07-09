FROM python:3.11-slim

LABEL name="httpbin"
LABEL description="A simple HTTP service for testing HTTP/3"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

WORKDIR /httpbin

# Pin the whole stack. These were previously unpinned, so a new gunicorn
# release (26.0.0) that dropped the bundled eventlet worker silently broke
# CI: gunicorn couldn't load `-k eventlet` and every request 502'd through
# Caddy. Pinning to a verified-good set keeps the backend reproducible.
RUN pip install --no-cache-dir \
    "httpbin==0.10.4" \
    "gunicorn==26.0.0" \
    "flask==3.1.3" \
    "werkzeug==3.1.8"

# Copy WSGI wrapper that fixes bytearray->bytes conversion
COPY wsgi_wrapper.py .

EXPOSE 80

# Threaded sync worker (gthread) ships with gunicorn, so there's no async
# worker (eventlet/gevent) to keep version-compatible. Caddy terminates
# HTTP/3 out front, so the backend only serves plain HTTP/1 here.
CMD ["gunicorn", "-b", "0.0.0.0:80", "wsgi_wrapper:app", "--workers", "4", "--threads", "4"]
