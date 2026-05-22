CC = gcc
CFLAGS = -Wall -Wextra -O2

LIBS = -lssl -lcrypto

TARGET_SERVER = server
TARGET_CLIENT = client

SRCS_COMMON = crypto.c

all: $(TARGET_SERVER) $(TARGET_CLIENT)

$(TARGET_SERVER): server.c $(SRCS_COMMON)
	$(CC) $(CFLAGS) server.c $(SRCS_COMMON) -o $(TARGET_SERVER) $(LIBS)

$(TARGET_CLIENT): client.c $(SRCS_COMMON)
	$(CC) $(CFLAGS) client.c $(SRCS_COMMON) -o $(TARGET_CLIENT) $(LIBS)

clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT) *.o
