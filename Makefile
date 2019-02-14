#
# Copyright (c) 2015 Vladimir Alemasov
# All rights reserved
#
# This program and the accompanying materials are distributed under 
# the terms of GNU General Public License version 2 
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#

TARGET = whsniff
OBJDIR = obj
SRCDIR = src
SOURCES = $(wildcard $(SRCDIR)/*.c)
HEADERS = $(wildcard $(SRCDIR)/*.h)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
DEPS = $(HEADERS)

INCLPATH = -I.
LIBS = -lusb-1.0

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    LIBS += -lrt
endif

# Installation directories by convention
# http://www.gnu.org/prep/standards/html_node/Directory-Variables.html
PREFIX = /usr/local
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
SYSCONFDIR = $(PREFIX)/etc
LOCALSTATEDIR = $(PREFIX)/var

# main goal
all: $(TARGET)

# target executable
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBPATH) $(LIBS)

# object files
$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c $(DEPS) | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(INCLPATH)

# create object files directory
$(OBJDIR):
	mkdir -p $(OBJDIR)

# clean
clean:
	rm -rf $(OBJDIR)

# distclean
distclean: clean
	rm -f $(TARGET)

# install
# http://unixhelp.ed.ac.uk/CGI/man-cgi?install
install: all
	install -d -m 755 "$(BINDIR)"
	install -m 755 $(TARGET) "$(BINDIR)/"

# uninstall
uninstall:
	rm -f $(BINDIR)/$(TARGET)

.PHONY: all clean distclean install uninstall
