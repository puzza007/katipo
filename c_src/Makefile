CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT = katipo

ERTS_INCLUDE_DIR ?= $(shell erl -noshell -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)]), halt().")
ERL_INTERFACE_INCLUDE_DIR ?= $(shell erl -noshell -eval "io:format(\"~s\", [code:lib_dir(erl_interface, include)]), halt().")
ERL_INTERFACE_LIB_DIR ?= $(shell erl -noshell -eval "io:format(\"~s\", [code:lib_dir(erl_interface, lib)]), halt().")

C_SRC_DIR = $(CURDIR)
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT)

UNAME_SYS := $(shell uname -s)

# Support custom curl installation via CURL_PREFIX environment variable
# This is used in CI for HTTP/3 support
ifdef CURL_PREFIX
	CURL_CONFIG = $(CURL_PREFIX)/bin/curl-config
endif

ifeq ($(UNAME_SYS), Darwin)
	CC ?= cc
	# Prefer homebrew curl for HTTP/3 support if available
	ifndef CURL_CONFIG
		HOMEBREW_CURL := $(wildcard /opt/homebrew/opt/curl/bin/curl-config)
		ifneq ($(HOMEBREW_CURL),)
			CURL_CONFIG = /opt/homebrew/opt/curl/bin/curl-config
		else
			CURL_CONFIG = curl-config
		endif
	endif
	CFLAGS ?= -O3 -std=c99 -Wall -Wmissing-prototypes $(shell pkg-config --cflags libevent)
	CXXFLAGS ?= -O3 -Wall
	LDFLAGS ?= -flat_namespace -undefined suppress $(shell pkg-config --libs libevent)
else ifeq ($(UNAME_SYS), FreeBSD)
	CC ?= cc
	CURL_CONFIG ?= curl-config
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes -I /usr/local/include
	CXXFLAGS ?= -O3 -finline-functions -Wall
	LDLIBS += -L /usr/local/lib
else ifeq ($(UNAME_SYS), Linux)
	CC ?= gcc
	CURL_CONFIG ?= curl-config
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
	LDLIBS += -L /usr/local/lib
endif

CFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR) -I $(ERL_INTERFACE_INCLUDE_DIR)
CXXFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR) -I $(ERL_INTERFACE_INCLUDE_DIR)

# Add curl include path from curl-config
CFLAGS += $(shell $(CURL_CONFIG) --cflags)

# Use CURL_CONFIG for curl libs
CURL_LIBS ?= $(shell $(CURL_CONFIG) --libs)
LDLIBS += $(CURL_LIBS) -L $(ERL_INTERFACE_LIB_DIR) -lei -levent

# Detect curl features
CURL_VERSION := $(shell $(CURL_CONFIG) --version)
CURL_FEATURES := $(shell $(CURL_CONFIG) --features)
HAS_HTTP3 := $(findstring HTTP3,$(CURL_FEATURES))
HAS_HTTP2 := $(findstring HTTP2,$(CURL_FEATURES))

c_verbose_0 = @echo " C     " $(?F);
c_verbose = $(c_verbose_$(V))

cpp_verbose_0 = @echo " CPP   " $(?F);
cpp_verbose = $(cpp_verbose_$(V))

link_verbose_0 = @echo " LD    " $(@F);
link_verbose = $(link_verbose_$(V))

SOURCES := $(shell find $(C_SRC_DIR) -type f \( -name "*.c" -o -name "*.C" -o -name "*.cc" -o -name "*.cpp" \))
OBJECTS = $(addsuffix .o, $(basename $(SOURCES)))

COMPILE_C = $(c_verbose) $(CC) $(CFLAGS) $(CPPFLAGS) -c
COMPILE_CPP = $(cpp_verbose) $(CXX) $(CXXFLAGS) $(CPPFLAGS) -c

# Default target
.PHONY: all
all: $(C_SRC_OUTPUT)

# Print build info (can be called separately with 'make info')
.PHONY: info
info:
	@echo "======================================"
	@echo "Katipo Build Configuration"
	@echo "======================================"
	@echo "curl-config: $(CURL_CONFIG)"
	@echo "curl version: $(CURL_VERSION)"
	@echo "curl features: $(CURL_FEATURES)"
	@echo ""
ifeq ($(HAS_HTTP3),HTTP3)
	@echo "HTTP/3 support: ENABLED"
else
	@echo "HTTP/3 support: DISABLED (curl not built with HTTP/3)"
endif
ifeq ($(HAS_HTTP2),HTTP2)
	@echo "HTTP/2 support: ENABLED"
else
	@echo "HTTP/2 support: DISABLED"
endif
	@echo "======================================"
	@echo ""

# Print info on first compile (when .o files don't exist)
$(C_SRC_OUTPUT): $(OBJECTS)
	@if [ ! -f $@ ]; then \
		echo "======================================"; \
		echo "Katipo Build Configuration"; \
		echo "======================================"; \
		echo "curl-config: $(CURL_CONFIG)"; \
		echo "curl version: $(CURL_VERSION)"; \
		echo "curl features: $(CURL_FEATURES)"; \
		echo ""; \
		if echo "$(CURL_FEATURES)" | grep -q HTTP3; then \
			echo "HTTP/3 support: ENABLED"; \
		else \
			echo "HTTP/3 support: DISABLED (curl not built with HTTP/3)"; \
		fi; \
		if echo "$(CURL_FEATURES)" | grep -q HTTP2; then \
			echo "HTTP/2 support: ENABLED"; \
		else \
			echo "HTTP/2 support: DISABLED"; \
		fi; \
		echo "======================================"; \
		echo ""; \
	fi
	@mkdir -p $(BASEDIR)/priv/
	$(link_verbose) $(CC) $(OBJECTS) $(LDFLAGS) $(LDLIBS) -o $(C_SRC_OUTPUT)

%.o: %.c
	$(COMPILE_C) $(OUTPUT_OPTION) $<

%.o: %.cc
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.C
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

%.o: %.cpp
	$(COMPILE_CPP) $(OUTPUT_OPTION) $<

clean:
	@rm -f $(C_SRC_OUTPUT) $(OBJECTS)
