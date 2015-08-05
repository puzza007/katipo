.PHONY: \
	all \
	clean \
	ensure-venv-exists \
	nuke \
	python \
	start-http-bin \
	stop-http-bin \
	test

all:
	@rebar3 compile

clean:
	@rebar3 clean

ensure-venv-exists:
	@virtualenv -q .

nuke: clean
	@rm -rf bin lib include _build man .Python

python: ensure-venv-exists
	@. bin/activate && pip install -r requirements.txt

start-http-bin: python
	@./bin/gunicorn --pid /tmp/katipo_gunicorn.pid --daemon httpbin:app

stop-http-bin:
	@if [ -e /tmp/katipo_gunicorn.pid ]; then \
		kill `cat /tmp/katipo_gunicorn.pid`; \
	fi

test: stop-http-bin start-http-bin
	@rebar3 ct
