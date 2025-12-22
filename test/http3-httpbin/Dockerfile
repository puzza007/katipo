FROM python:3.11-slim

LABEL name="httpbin"
LABEL description="A simple HTTP service for testing HTTP/3"

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

WORKDIR /httpbin

# Install httpbin and gunicorn directly via pip
# Use eventlet instead of gevent to avoid Cython build issues
RUN pip install --no-cache-dir httpbin gunicorn eventlet

# Copy WSGI wrapper that fixes bytearray->bytes conversion
COPY wsgi_wrapper.py .

EXPOSE 80

# Use our wrapper instead of httpbin:app directly
CMD ["gunicorn", "-b", "0.0.0.0:80", "wsgi_wrapper:app", "-k", "eventlet"]
