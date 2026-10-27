# Standalone build for the TUN demo.
# Only needs src/tun.c - no libsodium, no other modules.
#
#   make          build ./tun_demo
#   make run      build and run it with sudo
#   make clean    remove the binary

CC     := gcc
CFLAGS := -Wall -Wextra -std=c11 -g -O0 -I../include

TARGET := tun_demo
SRCS   := tun_demo.c ../src/tun.c

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SRCS) ../include/tun.h
	$(CC) $(CFLAGS) $(SRCS) -o $@

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
