#!/usr/bin/python
#-*-  coding:utf8 -*-


import sys,\
	   os,\
	   fcntl



# Global variables
EXCLUDE_PID = 5000
INCLUDE_PID = 5001
STOP_LOGGING = 5002
CONTINUE_LOGGING = 5003
CLEAR_RULES = 5004
DELETE_FROM_EXCLUDE = 5005
DELETE_FROM_INCLUDE = 5006
TRUNCATE_LOG_FILE = 5007



def SendCommand(fd, cmd, *args):
	if args:
		return fcntl.ioctl(fd, cmd)
	else:
		return fcntl.ioctl(fd, cmd, args[0])



def main():
	if len(sys.argv) < 3:
		print "Enter a device name, cmd number and probably optional parameters like pids or paths"
		return 10001
	
	try:
		fDev = file(sys.argv[1])
	except IOError as exc:
		print "Can't open {}".format(sys.argv[1])
		print exc
		return 10002
		
	if len(sys.argv) > 3:
		ret = SendCommand(fDev, sys.argv[2], sys.argv[3])
	else:
		ret = SendCommand(fDev, sys.argv[2])
	print "Return value: %d" % ret
	
	
	return 0



if __name__ == '__main__':
	main()
