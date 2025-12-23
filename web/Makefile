CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -g
GTK_FLAGS = $(shell pkg-config --cflags --libs gtk+-3.0 webkit2gtk-4.0)

all: browser tiny_server cgi-bin/adder

browser: build/browser_main.o build/browser_gui.o build/http_client.o build/html_parser.o
	$(CC) $(CFLAGS) -o $@ $^ $(GTK_FLAGS)

tiny_server: build/tiny.o
	$(CC) $(CFLAGS) -o $@ $^

cgi-bin/adder: build/adder.o
	@mkdir -p cgi-bin
	$(CC) $(CFLAGS) -o $@ $^

build/browser_main.o build/browser_gui.o: build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(shell pkg-config --cflags gtk+-3.0 webkit2gtk-4.0) -c $< -o $@

build/%.o: src/%.c
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf build browser tiny_server cgi-bin

.PHONY: all clean
