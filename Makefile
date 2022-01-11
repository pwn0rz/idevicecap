CFLAGS+=-g -Wall
LDFLAGS+=-limobiledevice-1.0 -lplist-2.0 -lpcap

idevicecap: src/idevicecap.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<