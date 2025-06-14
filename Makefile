
CFLAGS = -Wall -Wextra -Os -ggdb3
LIBS = -lpthread

all: gwproxy

gwproxy: gwproxy.c

clean:
	@rm -f gwproxy

.PHONY: all clean
