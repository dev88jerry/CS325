#!/usr/bin/env python3
import fcntl
import struct
import os
import ssl
import spwd
import crypt
from scapy.all import *

TUNSETIFF = 0x400454ca  # ioctl request code
IFF_TUN = 0x0001  # create a tunnel
IFF_TAP = 0x0002  # create a tap device
IFF_NO_PI = 0x1000  # don't pass on packet info

'''
Create the tun interface
'''
tun = os.open("/dev/net/tun", os.O_RDWR)  # open the tun device
# create the control block
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)  # create the interface

'''
Get the interface name
'''
ifname = ifname_bytes.decode(
    'UTF-8')[:16].strip("\x00")  # get the interface name
print("Interface Name: {}".format(ifname))  # print the interface name

'''
Set route
'''
os.system("ip addr add 192.168.53.1/24 dev {}".format(ifname))  # set the route
os.system("ip link set dev {} up".format(ifname))  # set the interface up

'''
Get certs
'''
SERVER_CERT = "/volumes/crt/server-certs/vpn.crt"  # server certificate
SERVER_PRIVATE = "/volumes/crt/server-certs/vpn.key"  # server private key

'''
Set SSL
'''
context_srv = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)  # create the SSL context
context_srv.num_tickets = 0  # disable session tickets
# load the server certificate
context_srv.load_cert_chain(SERVER_CERT, SERVER_PRIVATE)

'''
Set sock
'''
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM,
                     0)  # create the socket
sock.bind(("0.0.0.0", 443))  # bind the socket to the port
sock.listen(5)  # listen for connections
print(">>> Preparation done.")

'''
Initialization
'''
inputs = [sock, tun]  # create the input list
con_dict = {}  # create the connection dictionary
ip_dict = {}  # create the IP dictionary

'''
Main loop
'''
while True:
    ready, _, _ = select.select(inputs, [], [])  # select the ready inputs

    for fd in ready:  # for each ready input
        if fd is sock:  # if the input is the socket
            '''
            Acceppt a new connection and set up the connection
            '''
            con, addr = sock.accept()  # accept the connection
            IPa, _ = addr  # get the IP address
            # wrap the connection with SSL
            con = context_srv.wrap_socket(con, server_side=True)
            con.setblocking(0)  # set the socket to non-blocking

            print(">>> {} new connection".format(IPa))

            '''
            Receive the username and password.
            If they are all correct, add the connection to the listening list.
            '''
            usrname = b''  # create the username
            passwd = b''  # create the password

            re_client_auth = IP()  # create the packet to reply the client authentication
            re_client_auth.src = '192.168.53.1'  # set the source IP address

            while (usrname == b'') or (passwd == b''):  # while some data is not received
                # select the connection inputs
                ready, _, _ = select.select([con], [], [])
                for fd in ready:  # for each ready input
                    data = fd.recv(2048)  # receive the data
                    pkt = IP(data)  # create the packet
                    re_client_auth.dst = pkt.src  # set the destination IP address
                    if usrname == b'':  # if the username is not received
                        usrname = pkt[Raw].load  # get the username
                    else:  # if the username is received but the password is not received
                        passwd = pkt[Raw].load  # get the password

            try:
                # get the password
                pw1 = spwd.getspnam(usrname.decode()).sp_pwd
                # get the encrypted password
                pw2 = crypt.crypt(passwd.decode(), pw1)
            except KeyError:  # if the username is not found
                # message to the client
                con.sendall(bytes(re_client_auth/b'0'))
                con.close()  # close the connection
                print(">>> {} login failed - WRONG USERNAME".format(IPa))
            else:  # if the username is found
                if pw1 != pw2:  # if the password is not correct
                    # message to the client
                    con.sendall(bytes(re_client_auth/b'0'))
                    con.close()  # close the connection
                    print(">>> {} login failed - WRONG PASSWORD".format(IPa))
                else:  # if the password is correct
                    # message to the client
                    con.sendall(bytes(re_client_auth/b'1'))
                    inputs.append(con)  # add the connection to the input list
                    print(">>> {} login succeed".format(IPa))

        elif fd is tun:  # if the input is the tun interface
            packet = os.read(tun, 2048)  # read the packet
            pkt = IP(packet)  # create the packet
            print("=== TUN:\t{}\t-->\t{}\t===".format(pkt.src, pkt.dst))
            # send the packet to the destination
            con_dict[pkt.dst].sendall(packet)
        else:  # if the input is the connection
            data = fd.recv(2048)  # receive the data
            if data != b'':  # if the data is not empty
                pkt = IP(data)  # create the packet
                print("=== SOCKET:\t{}\t-->\t{}\t===".format(pkt.src, pkt.dst))
                if pkt.src not in con_dict:  # if the source IP is not in the dictionary
                    # add the connection to the dictionary
                    con_dict[pkt.src] = fd
                    # add the IP address to the IP dictionary
                    ip_dict[fd] = pkt.src
                # write the packet to the tun interface
                os.write(tun, bytes(pkt))
            else:  # if the data is empty
                print(">>> {} connection closed.".format(ip_dict[fd]))
                inputs.remove(fd)  # remove the connection from the input list
                # remove the IP from the connection dictionary
                del con_dict[ip_dict[fd]]
                del ip_dict[fd]  # remove the connection from the IP dictionary
                fd.close()  # close the connection
