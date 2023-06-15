import sys
import capstone

a = open('/tmp/ls_0x4d50-0x16f81.bin', 'rb').read()

entry_offset = 0x6b60
entry_offset = 0x4d50

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

b = md.disasm(a, entry_offset)

counter = 0

for i in b:
    #break
    print(i, i.id)
    counter += 1

    if counter == 20:
        pass
        #break

sys.exit(0)

a = open('/tmp/ls_0x17000-0x1c1e7.bin', 'rb').read()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

entry_offset = 0x17000

b = md.disasm(a, entry_offset)

for i in b:
    print(i, i.id)
    counter += 1

    if counter == 20:
        pass
        #break
