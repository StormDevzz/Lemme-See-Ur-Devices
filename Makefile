# анализатор устройств - мульти-языковая система сборки
# цель: linux x86_64

CC = gcc
AS = nasm
LUA_CFLAGS = $(shell pkg-config --cflags lua5.4 2>/dev/null || pkg-config --cflags lua 2>/dev/null || echo "-I/usr/include/lua5.4")
LUA_LIBS = $(shell pkg-config --libs lua5.4 2>/dev/null || pkg-config --libs lua 2>/dev/null || echo "-llua5.4 -lm -ldl")

PY_CFLAGS = $(shell python3-config --cflags 2>/dev/null)
PY_LDFLAGS = $(shell python3-config --ldflags --embed 2>/dev/null || python3-config --ldflags 2>/dev/null)

CFLAGS = -Wall -Wextra -O2 -std=c11 -D_GNU_SOURCE $(LUA_CFLAGS) $(PY_CFLAGS)
LDFLAGS = -lncursesw -lpthread -ludev $(LUA_LIBS) $(PY_LDFLAGS)
ASFLAGS = -f elf64

# директории
SRC_DIR = src
ASM_DIR = asm
LUA_DIR = lua
PY_DIR = python
BUILD_DIR = build
BIN_DIR = bin

# исходные файлы
C_SOURCES = $(wildcard $(SRC_DIR)/*.c)
ASM_SOURCES = $(wildcard $(ASM_DIR)/*.asm)

# объектные файлы
C_OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(C_SOURCES))
ASM_OBJECTS = $(patsubst $(ASM_DIR)/%.asm,$(BUILD_DIR)/%.o,$(ASM_SOURCES))

# целевой файл
TARGET = $(BIN_DIR)/device_analyzer

.PHONY: all clean install dirs

all: dirs $(TARGET) lua_scripts

dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(ASM_DIR)/%.asm
	$(AS) $(ASFLAGS) $< -o $@

$(TARGET): $(C_OBJECTS) $(ASM_OBJECTS)
	$(CC) $^ -o $@ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

lua_scripts:
	@cp $(LUA_DIR)/*.lua $(BIN_DIR)/ 2>/dev/null || true
	@echo "Lua scripts copied"

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)

install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install -y build-essential nasm libncursesw5-dev libudev-dev liblua5.3-dev python3 python3-pip

# помощники для разработки
debug: CFLAGS += -g -DDEBUG
debug: clean all

run: all
	./$(TARGET)
