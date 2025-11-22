all: main.c e46_checksum.c
	$(CC) main.c e46_checksum.c -g -lpcap -o ipchecksum

clean:
	rm ipchecksum