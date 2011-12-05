SOURCES=main.c portscan.c buildpacket.c captpacket.c
OBJECTS=main.o portscan.o buildpacket.o captpacket.o
OPTIONS=-g -Wall
LINK_FLAGS=-lnet -lpcap
TARGET=sps
CC=cc

$(TARGET): $(OBJECTS)
	$(CC) $(OPTIONS) -o $(TARGET) $(OBJECTS) $(LINK_FLAGS)
$(OBJECTS): $(SOURCES)
	$(CC) -c -g $(SOURCES)
all:
	make $(TARGET)
clean:
	rm -f *.o
	rm -f $(TARGET)
