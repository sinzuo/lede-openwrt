SOURCES=$(wildcard *.c)
OBJS=$(patsubst %.c,%.o,$(SOURCES))
LIBA=libudpreport.a
TARGET=udpreport

CFLAGS += -O2 -Wno-error=format-security

all:$(TARGET) $(LIBA)

$(TARGET):$(LIBA)
	$(CC) -L.  $^ -o $@ -ljson-c -lpthread -luci

$(LIBA):$(OBJS)
	$(AR) cr $@ $^

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f *.o  $(OBJS) $(LIBA) $(TARGET)
