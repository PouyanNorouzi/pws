CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
BUILD_DIR = build
SRC_DIR = src
EXE = $(BUILD_DIR)/main
OBJECTS = $(BUILD_DIR)/main.o $(BUILD_DIR)/pssh.o

$(shell mkdir -p $(BUILD_DIR))

$(EXE) : $(OBJECTS)
			$(CC) $(CFLAGS) -o $(EXE) $(OBJECTS)

$(BUILD_DIR)/main.o : $(SRC_DIR)/main.c include/pssh.h
			$(CC) $(CFLAGS) -c $(SRC_DIR)/main.c -o $(BUILD_DIR)/main.o 

$(BUILD_DIR)/pssh.o : $(SRC_DIR)/pssh.c include/pssh.h
			$(CC) $(CFLAGS) -c $(SRC_DIR)/pssh.c -o $(BUILD_DIR)/pssh.o 

.PHONY : rm

rm :
			rm -rf $(BUILD_DIR)