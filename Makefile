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
	aarch64-none-elf-g++ $(ARCH) -c out/main.text.s -o out/main.text.o
#	aarch64-none-elf-g++ $(ARCH) -c out/main.rodata.s -o out/main.rodata.o
#	aarch64-none-elf-g++ $(ARCH) -c out/main.data.s -o out/main.data.o
#	aarch64-none-elf-g++ $(ARCH) -c out/main.bss.s -o out/main.bss.o
	
#	aarch64-none-elf-g++ $(ARCH) out/main.text.o out/main.rodata.o out/main.data.o out/main.bss.o -o out/main.elf