
$(CFLAGS) += -O2 -Wall

all: ibpsolve

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

ibpsolve: main.o hashtable.o
	$(CC) -lpcap -o $@ $^

clean:
	rm -f *.o ibpsolve
