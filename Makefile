BUILD := build
SRC := src
TARGET := nsostuff

SRC_DIRS = $(shell find $(SRC) -type d)
SRC_C = $(shell find $(SRC) -name *.c)
SRC_CPP = $(shell find $(SRC) -name *.cpp)
SRC_ASM = $(shell find $(SRC) -name *.s)

$(shell mkdir -p $(SRC_DIRS:$(SRC)%=$(BUILD)%))

OBJS = 	$(SRC_C:$(SRC)/%.c=$(BUILD)/%.o) \
		$(SRC_CPP:$(SRC)/%.cpp=$(BUILD)/%.o) \
		$(SRC_ASM:$(SRC)/%.s=$(BUILD)/%.o)

ARCH	:=	-march=armv8-a+crc+crypto -mtune=cortex-a57

LD 	:= clang++
CXX := clang++
CC 	:= clang

$(BUILD)/%.o: $(SRC)/%.c
	$(CC) -g -c $< -o $@

$(BUILD)/%.o: $(SRC)/%.cpp
	$(CXX) -g -c $< -o $@

$(BUILD)/%.o: %.s
	$(CC) -c $< -o $@

all: $(OBJS)
	$(LD) $^ -o $(TARGET) -lcapstone

clean:
	rm -rf $(BUILD) $(TARGET)
	
asm:
	aarch64-none-elf-g++ -L $(ARCH) -T out/app.ld out/full.s -o out/full.o -nostartfiles