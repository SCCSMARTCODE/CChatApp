CC = gcc
CFLAGS = -Wall -Werror -Wextra `pkg-config --cflags gtk+-3.0`
LDFLAGS = `pkg-config --libs gtk+-3.0`
BUILD_DIR = build
BIN_DIR = bin

CLIENT_SRCS = socket_client/main.c utils/utils.c
CLIENT_OBJS = $(CLIENT_SRCS:%.c=$(BUILD_DIR)/%.o)
CLIENT_BIN = $(BIN_DIR)/client

SERVER_SRCS = socket_server/main.c utils/utils.c
SERVER_OBJS = $(SERVER_SRCS:%.c=$(BUILD_DIR)/%.o)
SERVER_BIN = $(BIN_DIR)/server

all: $(CLIENT_BIN) $(SERVER_BIN)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/socket_client
	mkdir -p $(BUILD_DIR)/socket_server
	mkdir -p $(BUILD_DIR)/utils

$(CLIENT_BIN): $(CLIENT_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SERVER_BIN): $(SERVER_OBJS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
