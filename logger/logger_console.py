#!/usr/bin/python
#-*-  coding:utf8 -*-


import sys,\
	   os,\
	   subprocess
import ioctls



# Global variables
module_name_pref = 'driver.ko'
module_name = 'driver'
device_name = '/dev/logger_driver'
commands = str()



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
		["/sbin/rmmod ", module_name],
		stderr = subprocess.PIPE
	)
	ret = proc.wait()
	if ret:
		msg = "Message from rmmod: '{}'".format(proc.stderr.read()[:])
		print msg.replace('\n', '')
		return False
	return True


def CreateChilds(cmds):
	proc = subprocess.Popen(
		cmds,
		shell = True,
		stdout = subprocess.PIPE,
		stderr = subprocess.PIPE
	)
	ret = proc.wait()
	
	if ret:
		print ("Error output of subprocess: {}".format(proc.stderr.read()))
	else:
		print ("Output of subprocess: {}".format(proc.stdout.read()))
	
	return ret



def main():
	if len(sys.argv) < 2 or sys.argv[1] == '-h':
		print "Run so: ./script <commands_for_log_processing>\n"\
			  "Example 1: ./logger_console.py tail -f /tmp/logger_driver.log\n"\
			  "Example 2: ./logger_console.py tail -f /tmp/logger_driver.log | grep '.*Read.*'"
		return 10001
	
	if not ioctls.CheckRoot():
		print "Need run as root"
		return 10002
	commands = sys.argv[1:]
	
	if not LoadKernelModule(module_name_pref):
		print "Can't load module: {}".format(module_name_pref)
		return 10003
	
	try:
		fDev = open(device_name)
	except IOError as Exc:
		print "Can't open {}".format(device_name)
		print Exc
		UnloadKernelModule(module_name)
		return 10004
	
	ioctls.SendCommand(fDev, ioctls.STOP_LOGGING)
	ioctls.SendCommand(fDev, ioctls.TRUNCATE_LOG_FILE)
	CreateChilds(commands)
	
	UnloadKernelModule(module_name)
	
	
	return 0

	   
	   
if __name__ != '__main__':
	raise RuntimeError("Can't run like a module") 
else:
	try:
		main()
	except Exception as Exc:
		UnloadKernelModule(module_name)
		print Exc
