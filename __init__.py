from binaryninja import *


image_base = 0x00400000


def deobfuscate_cond_x86(bv):
    bwriter = BinaryWriter(bv)
    breader = BinaryReader(bv)
    instructions = [(insns, addr) for insns, addr in bv.instructions]
    for insn, addr in instructions:
        breader.seek(addr)
        b1 = ord(breader.read(1))
        if b1 >= 0x70 and b1 <= 0x7f:
            d1 = ord(breader.read(1))
            b2 = ord(breader.read(1))
            d2 = ord(breader.read(1))
            if (b1 ^ b2) == 0x01 and abs(d1 - d2) == 2:
                bwriter.seek(addr)
                bwriter.write("\xeb")
                bwriter.seek(addr + 2)
                bwriter.write("\x90\x90")
                log_info("Modified address " + hex(addr))
        if b1 == 0x0f:
            b1_1 = ord(breader.read(1))
            if b1_1 >= 0x80 and b1_1 <= 0x8f:
                d1 = breader.read32()
                b2 = ord(breader.read(1))
                if b2 == 0x0f:
                    b2_1 = ord(breader.read(1))
                    if b2_1 >= 0x80 and b2_1 <= 0x8f:
                        d2 = breader.read32()
                        if (b1_1 ^ b2_1) == 1 and abs(d1 - d2) == 6:
                            bwriter.seek(addr)
                            bwriter.write("\xe9")
                            bwriter.write32(d1 + 1)
                            bwriter.write("\x90\x90\x90\x90\x90\x90\x90")
                            log_info("Modified address " + hex(addr))


def add_functions(bv):
    start = AddressField("Start Address")
    end   = AddressField("End Address")
    if get_form_input([start, end], "Specify Pointer Range"):
        br = BinaryReader(bv)
        for pointer in range(start.result, end.result, 4):
            br.seek(pointer)
            addr = br.read32()
            bv.add_function(addr)


def find_bytecode(bv):
    rva_data = 0x2cda
    rva_size = 0x2cd6
    b_reader = BinaryReader(bv)

    b_reader.seek(image_base + rva_size)
    size = b_reader.read32()

    b_reader.seek(image_base + rva_data)
    data = b_reader.read32()

    return (data, size)




def dump_bytecode(bv):
    bytecode_rva, size = find_bytecode(bv)
    print hex(bytecode_rva)
    print hex(size)
    if size:
        # bytecode is compressed
        # TODO
        pass
    else:
        log_info("VM bytecode is uncompressed. Unable to dump, due to unknown size")


PluginCommand.register("x86 Conditional Branch Deobfuscator", "Removes the popular conditional branch obfuscation in x86 assembly", deobfuscate_cond_x86)
PluginCommand.register("Add Functions...", "Register functions based on range of pointers", add_functions)
PluginCommand.register("Dump FinSpy Bytecode", "Fetch, decompress, decrypt the FinSpy bytecode and dump it to disk", dump_bytecode)