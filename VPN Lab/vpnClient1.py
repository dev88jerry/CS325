#!/usr/bin/env python3

import fcntl
import struct
import os
import socket
import ssl
import getpass
from scapy.all import *

TUNSETIFF = 0x400454ca # ioctl request code
IFF_TUN = 0x0001 # create a tunnel
IFF_TAP = 0x0002 # create a tap device
IFF_NO_PI = 0x1000 # don't pass on packet info

hostname = 'vpnlabserver.com' # hostname of the server
port = 443 # port of the server
cadir = '/volumes/crt/client-certs' # directory of the client certificates

'''
Set up the TLS context
'''
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) # create the SSL context

context.load_verify_locations(capath=cadir) # load the client certificates
context.verify_mode = ssl.CERT_REQUIRED # verify the client certificates
context.check_hostname = True # check the hostname of the server

'''
Create TCP connection
'''
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create the socket
sock.connect((hostname, port)) # connect to the server

'''
Add the TLS
'''
try:
    ssock = context.wrap_socket( # wrap the socket with TLS
        sock, server_hostname=hostname, do_handshake_on_connect=False)
    ssock.do_handshake() # do the TLS handshake
except: # if the TLS handshake fails
    print(">>> Certificate failed") # print error message
    ssock.shutdown(socket.SHUT_RDWR) # shutdown the socket
    ssock.close() # close the socket
    exit() # exit the program
print("Server hostname: {}".format(ssock.server_hostname)) # print the server hostname

'''
Create the tun interface
'''
tun = os.open("/dev/net/tun", os.O_RDWR) # open the tun device
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI) # create the control block
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr) # create the interface

'''
Get the interface name
'''
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00") # get the interface name
print("Interface Name: {}".format(ifname)) # print the interface name

os.system("ip addr add 192.168.53.3/24 dev {}".format(ifname)) # set the route
os.system("ip link set dev {} up".format(ifname)) # set the interface up
os.system("ip route add 192.168.60.0/24 dev {} via 192.168.53.3".format(ifname)) # set the route

print(">>> Preparation done.")

'''
Login
'''
usrname = input("Input username: ") # input the username
passwd = getpass.getpass("Input password: ") # input the password
client_auth = IP()
client_auth.src = '192.168.53.3' # set the source IP address
client_auth.dst = '192.168.53.1' # set the destination IP address
ssock.send(bytes(client_auth/bytes(usrname.encode()))) # send the username
ssock.send(bytes(client_auth/bytes(passwd.encode()))) # send the password

ready, _, _ = select.select([ssock, tun], [], []) # wait for the server to send
for fd in ready:
    data = ssock.recv(2048) # receive the data
    pkt = IP(data) # create the packet
    client_auth_result = pkt[Raw].load # get the result
    if client_auth_result == b'0': # if the result is 0
        print(">>> Login failed") # print error message
        print(">>> Server closed") 
        ssock.shutdown(socket.SHUT_RDWR) # shutdown the socket
        ssock.close() # close the socket
        exit() # exit the program
print(">>> Login succeed")

'''
Main loop
'''
while True:
    ready, _, _ = select.select([ssock, tun], [], []) # wait for the server to send

    for fd in ready: # for each file descriptor
        if fd is tun: # if the file descriptor is the tun device
            packet = os.read(tun, 2048) # read the packet
            pkt = IP(packet) # create the packet
            print("=== TUN:\t{}\t-->\t{}\t===".format(pkt.src, pkt.dst)) 
            ssock.send(packet) # send the packet
        if fd is ssock: # if the file descriptor is the socket
            data = ssock.recv(2048) # receive the data
            if data != b'': # if the data is not empty
                # print (">>> Receive {} from {}".format(data, fd.getpeername()))
                pkt = IP(data) # create the packet
                print("=== SOCKET:\t{}\t-->\t{}\t===".format(pkt.src, pkt.dst))
                os.write(tun, bytes(pkt)) # send the packet to the tun device
            else: # if the data is empty
                print(">>> Server closed") 
                ssock.shutdown(socket.SHUT_RDWR) # shutdown the socket
                ssock.close() # close the socket
                exit() # exit the program
