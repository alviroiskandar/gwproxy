
CFLAGS = -Wall -Wextra -O2 -ggdb3
LIBS = -lpthread

all: gwproxy

gwproxy: gwproxy.c

clean:
	@rm -f gwproxy

.PHONY: all clean
