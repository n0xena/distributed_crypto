CC := gcc
JAVA_HOME := /usr/lib/jvm/default
JNI_INC := $(JAVA_HOME)/include
JNI_LINUX := $(JNI_INC)/linux
SRC_DIR := ./src
HEADER_DIR := ./header
INC_DIR := ../libtss/libtss-ffi
BUILD_DIR := ./build
TARGET := liblibtss_jni.so
CFLAGS := -Wall -Wextra -O2 -fPIC \
	  -I$(JNI_INC) \
	  -I$(JNI_LINUX) \
	  -I$(INC_DIR) \
	  -I$(HEADER_DIR)
LDFLAGS := -shared
LIB_DIR := -L../libtss/target/release
LIB := -llibtss_ffi
SOURCES := $(wildcard $(SRC_DIR)/*.c)
OBJECTS := $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIB_DIR) $(LIB)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
