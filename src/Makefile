
CFLAGS+=-O2 -Wall

all: ibpsolve

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

ibpsolve: main.o hashtable.o
	$(CC) -o $@ $^ -lpcap

clean:
	rm -f *.o ibpsolve
