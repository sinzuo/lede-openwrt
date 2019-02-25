SOURCES=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SOURCES))
EXEC += wireguard

CFLAGS += -DDEBUG

all: $(EXEC)

$(EXEC):$(OBJS)
	echo "ok"
clean:
	-rm -f $(EXEC) *.elf *.gdb *.o
