CC=g++
CPFLAGS= -g -Wall
LDFLAGS= -lpthread -lpcap

SRC= portScanner.cpp 
OBJ=$(SRC:.cpp=.o)
BIN=portScanner

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) $(LDFLAGS) -o $(BIN) $(OBJ) 


%.o:%.c
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
