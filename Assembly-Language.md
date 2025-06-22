###Assembly Language Cheat Sheet:

Create Assembly Code File:

nano mov.s


Assemble file and make it executable: (.s, .as, .asm)

nasm -f elf64 mov.s

ld -o mov mov.o

chmod 777 mov


Disassemble executable file:

objdump -M intel -d mov

objdump -sj .data mov

objdump -M intel --no-show-raw-insn --no-addresses -d mov

Install GEF for easy debugging:

wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py

echo source ~/.gdbinit-gef.py >> ~/.gdbinit

Run GDB with GEF:

gdb -q .\mov


Look at functions an variables:

gef➤  info functions

gef➤  info variables

Disassemble function:

gef➤  disas _start

Set Breakpoint, Run and Step-Into:

gef➤  b _start

gef➤  r

gef➤  si

gef➤  step

Examine registers or variables:
Argument 	Description 	Example
Count 	The number of times we want to repeat the examine 	2, 3, 10
Format 	The format we want the result to be represented in 	x(hex), s(string), i(instruction)
Size 	The size of memory we want to examine 	b(byte), h(halfword), w(word), g(giant, 8 bytes)

gef➤  x/4ig $rip

gef➤  x/s 0x402000

gef➤  registers

Write values to addresses:

gef➤  help patch


Searchable Linux Syscall table

https://filippo.io/linux-syscall-table/


