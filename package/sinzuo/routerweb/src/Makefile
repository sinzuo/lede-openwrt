SOURCES=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SOURCES))
TARGET=routerweb

CFLAGS += -O2 

all:$(TARGET)

$(TARGET):$(OBJS)
#	$(CC) $^ -o $@
	echo "ok"

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f *.o  $(OBJS) $(TARGET)
