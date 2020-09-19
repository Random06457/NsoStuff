$(shell mkdir -p build)

BUILD := build
SRC := src
TARGET := nsostuff

OBJS = $(addprefix $(BUILD)/, lz4.o main.o Nso.o Utils.o sha256.o Disassembler.o)

ARCH	:=	-march=armv8-a+crc+crypto -mtune=cortex-a57

$(BUILD)/%.o: $(SRC)/%.c
	@echo Building $@
	g++ -g -c $< -o $@

$(BUILD)/%.o: $(SRC)/%.cpp
	@echo Building $@
	g++ -g -c $< -o $@

$(BUILDDIR)/%.o: %.s
	@echo Building $@
	g++ -c $< -o $@

	

all: $(OBJS)
	g++ $^ -o $(TARGET) -lcapstone

clean:
	rm -rf $(BUILD) $(TARGET)
	
asm:
	aarch64-none-elf-g++ -L $(ARCH) -T out/app.ld out/full.s -o out/full.o -nostartfiles