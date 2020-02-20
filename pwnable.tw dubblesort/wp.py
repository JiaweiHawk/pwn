#coding:utf-8
from pwn import *

context.log_level = 'debug'
debug = 1


def exp(debug):
	if debug == 1:
		r = process(['./dubblesort'], env = {"LD_PRELOAD":'./dubblesort_lib'})
		#r = process('./dubblesort')
		#gdb.attach(r)
		#pause()

	r.recv()


exp(debug)
