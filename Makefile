CC=gcc
INCLUDE=-I/usr/local/include

LDFLAGS=

LIBS=-L/usr/local/ssl/lib -lssl -lcrypto -ldl

TARGET1 = server
TARGET2 = client

SOURCES1 = echo_mpserv.c
OBJS1 = $(SOURCES1:.c=.o)
SOURCES2 = echo_client.c
OBJS2 = $(SOURCES2:.c=.o)

all : $(TARGET1) $(TARGET2)

clean:
	$(RM) $(TARGET1) $(TARGET2) $(OBJS1) $(OBJS2)

$(TARGET1) : $(OBJS1)
	$(CC) -o $(TARGET1) $(OBJS1) $(LDFLAGS) $(LIBS)
	
$(TARGET2) : $(OBJS2)
	$(CC) -o $(TARGET2) $(OBJS2) $(LDFLAGS) $(LIBS)
	
%.o: %.c
	$(CC) $(INCLUDE) -o $@ -c $<
