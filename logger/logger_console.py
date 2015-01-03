#!/usr/bin/python
#-*-  coding:utf8 -*-


import sys,\
	   os,\
	   subprocess,\
	   time
import ioctls



# Global variables
module_name_pref = 'logger_driver.ko'
module_name = 'logger_driver'



def LoadKernelModule(module_path):
	print ("Loading the driver: {0}".format(module_name_pref))
	proc = subprocess.Popen(
		["/sbin/insmod", module_path],
		stderr = subprocess.PIPE
	)
	ret = proc.wait()
	if ret:
		msg = "Message from insmod: '{}'".format(proc.stderr.read()[:])
		print msg.replace('\n', '')
		return False
	return True


def UnloadKernelModule(module_name):
	print ("Unloading the driver: {0}".format(module_name))
	proc = subprocess.Popen(
		["/sbin/rmmod", module_name],
		stderr = subprocess.PIPE
	)
	ret = proc.wait()
	if ret:
		msg = "Message from rmmod: '{}', ret: {}".format(proc.stderr.read(), ret)
		print msg.replace('\n', '')
		return False
	return True


def main():
	if not ioctls.CheckRoot():
		print "Need run as root"
		return 10002
	
	if not LoadKernelModule(module_name_pref):
		print "Can't load module: {}".format(module_name_pref)
		return 10003
	
	try:
		fDev = open(ioctls.device_name)
	except IOError as Exc:
		print "Can't open {}".format(ioctls.device_name)
		print Exc
		UnloadKernelModule(module_name)
		return 10004
	
	ioctls.SendCommand(fDev, ioctls.STOP_LOGGING)
	time.sleep(1)
	ioctls.SendCommand(fDev, ioctls.TRUNCATE_LOG_FILE)
	
	print ("Driver has started")
	
	
	return 0

	   
	   
if __name__ != '__main__':
	raise RuntimeError("Can't run like a module") 
else:
	try:
		main()
	except BaseException as Exc:
		UnloadKernelModule(module_name)
		print Exc
	except:
		UnloadKernelModule(module_name)
		print ("Unknown exception")
