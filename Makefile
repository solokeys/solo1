src = $(wildcard *.c)
obj = $(src:.c=.o)

LDFLAGS = -Wl,--gc-sections ./tinycbor/lib/libtinycbor.a
CFLAGS = -O2 -fdata-sections -ffunction-sections -I./tinycbor/src

name = main

$(name):  $(obj)
	$(CC) $(LDFLAGS) -o $@ $(obj) $(LDFLAGS)

clean:
	rm -f *.o main.exe main
