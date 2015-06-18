# make - Ubuntu debug
# make release - Ubuntu release
# make openwrt - OpenWrt release

TARGET = whsniff
SOURCES = $(wildcard *.c)
HEADERS = $(wildcard *.h)
OBJECTS = $(SOURCES:.c=.o)
DEPS = $(HEADERS)

# ubuntu
INCLPATH = -I.
LIBPATH = -L/usr/lib
LIBS = -lusb-1.0 -lrt

# Ubuntu debug
FLAGS = -g -O2
debug: $(TARGET)

$(TARGET): $(OBJECTS) $(DEPS)
	$(CC) $(LDFLAGS) $(STATIC) -o $(TARGET) $(OBJECTS) $(LIBPATH) $(LIBS)

$(OBJECTS): $(SOURCES)
	$(CC) $(FLAGS) $(CFLAGS) $(DEF) -c $(SOURCES) $(INCLPATH)


# Ubuntu release
.PHONY: release
release: FLAGS = -O2 -DNDEBUG
release: $(TARGET)


# OpenWrt
.PHONY: openwrt
openwrt: FLAGS = -O2
openwrt: INCLPATH = $(TARGET_INCLPATH)
openwrt: LIBPATH = $(TARGET_LIBPATH)
openwrt: LIBS = $(TARGET_LIBS)
openwrt: DEF = $(TARGET_DEFS)
openwrt: $(TARGET)

.PHONY: clean
clean:
	rm -f $(OBJECTS) $(TARGET)
