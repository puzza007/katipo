CURDIR := $(shell pwd)
BASEDIR := $(abspath $(CURDIR)/..)

PROJECT = katipo

ERTS_INCLUDE_DIR ?= $(shell erl -noshell -eval "io:format(\"~s/erts-~s/include/\", [code:root_dir(), erlang:system_info(version)]), halt().")
ERL_INTERFACE_INCLUDE_DIR ?= $(shell erl -noshell -eval "io:format(\"~s\", [code:lib_dir(erl_interface, include)]), halt().")
ERL_INTERFACE_LIB_DIR ?= $(shell erl -noshell -eval "io:format(\"~s\", [code:lib_dir(erl_interface, lib)]), halt().")

C_SRC_DIR = $(CURDIR)
C_SRC_OUTPUT ?= $(CURDIR)/../priv/$(PROJECT)

UNAME_SYS := $(shell uname -s)
ifeq ($(UNAME_SYS), Darwin)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -Wall -Wmissing-prototypes $(shell pkg-config --cflags libevent)
	CXXFLAGS ?= -O3 -Wall
	LDFLAGS ?= -flat_namespace -undefined suppress $(shell pkg-config --libs libevent)
else ifeq ($(UNAME_SYS), FreeBSD)
	CC ?= cc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes -I /usr/local/include
	CXXFLAGS ?= -O3 -finline-functions -Wall
	LDLIBS += -L /usr/local/lib
else ifeq ($(UNAME_SYS), Linux)
	CC ?= gcc
	CFLAGS ?= -O3 -std=c99 -finline-functions -Wall -Wmissing-prototypes
	CXXFLAGS ?= -O3 -finline-functions -Wall
endif

CFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR) -I $(ERL_INTERFACE_INCLUDE_DIR)
CXXFLAGS += -fPIC -I $(ERTS_INCLUDE_DIR) -I $(ERL_INTERFACE_INCLUDE_DIR)

CURL_LIBS ?= $(shell curl-config --libs)
LDLIBS += $(CURL_LIBS) -L $(ERL_INTERFACE_LIB_DIR) -lei -levent

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

$(C_SRC_OUTPUT): $(OBJECTS)
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
