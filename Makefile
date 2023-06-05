LDLIBS=-lpcap

all: airodump

airodump: main.o mac.o radiotap.o beacon.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f airodump *.o