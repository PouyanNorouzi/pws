CC = gcc
LIBS = -lssh
CFLAGS = -Wall -Wextra -Iinclude 
BUILD_DIR = build
SRC_DIR = src
EXE = $(BUILD_DIR)/main
OBJECTS = $(BUILD_DIR)/main.o $(BUILD_DIR)/pssh.o
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux)
    LIBS += -lbsd
endif

include .env

$(shell mkdir $(BUILD_DIR))

$(EXE) : $(OBJECTS)
			$(CC) $(CFLAGS) -o $(EXE) $(OBJECTS) $(LIBS) 

$(BUILD_DIR)/main.o : $(SRC_DIR)/main.c include/pssh.h
			$(CC) $(CFLAGS) -c $(SRC_DIR)/main.c -o $(BUILD_DIR)/main.o 

$(BUILD_DIR)/pssh.o : $(SRC_DIR)/pssh.c include/pssh.h
			$(CC) $(CFLAGS) -c $(SRC_DIR)/pssh.c -o $(BUILD_DIR)/pssh.o 

.PHONY : rm

rm :
			rm -rf $(BUILD_DIR)

run: $(EXE)
			./$(EXE) $(HOST)