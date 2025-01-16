CC = gcc
LIBS = -lssh
CFLAGS = -Wall -Wextra -Iinclude 
BUILD_DIR = build
SRC_DIR = src
EXE = $(BUILD_DIR)/main
OBJECTS = $(BUILD_DIR)/main.o $(BUILD_DIR)/pssh.o $(BUILD_DIR)/attr_list.o $(BUILD_DIR)/dynamic_str.o \
			$(BUILD_DIR)/path.o
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux)
    LIBS += -lbsd
endif

include .env

$(shell mkdir -p $(BUILD_DIR))

$(EXE) : $(OBJECTS)
			$(CC) $(CFLAGS) -o $(EXE) $(OBJECTS) $(LIBS) 

$(BUILD_DIR)/main.o : $(SRC_DIR)/main.c include/pssh.h
			$(CC) $(CFLAGS) -c $(SRC_DIR)/main.c -o $(BUILD_DIR)/main.o 

$(BUILD_DIR)/pssh.o : $(SRC_DIR)/pssh.c include/pssh.h
			$(CC) $(CFLAGS) -c $(SRC_DIR)/pssh.c -o $(BUILD_DIR)/pssh.o 

$(BUILD_DIR)/attr_list.o: $(SRC_DIR)/attr_list.c include/attr_list.h
			$(CC) $(CFLAGS) -c $(SRC_DIR)/attr_list.c -o $(BUILD_DIR)/attr_list.o 

$(BUILD_DIR)/dynamic_str.o: $(SRC_DIR)/dynamic_str.c include/dynamic_str.h
			$(CC) $(CFLAGS) -c $(SRC_DIR)/dynamic_str.c -o $(BUILD_DIR)/dynamic_str.o 

$(BUILD_DIR)/path.o: $(SRC_DIR)/path.c include/path.h
			$(CC) $(CFLAGS) -c $(SRC_DIR)/path.c -o $(BUILD_DIR)/path.o 

.PHONY : rm

rm :
			rm -rf $(BUILD_DIR)

run: $(EXE)
			./$(EXE) $(HOST)