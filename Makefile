
CFLAGS = -Wall -Wextra -O0 -ggdb3 -fsanitize=address -fsanitize=undefined
LIBS = -lpthread

all: gwproxy

gwproxy: gwproxy.c

clean:
	@rm -f gwproxy

.PHONY: all clean
