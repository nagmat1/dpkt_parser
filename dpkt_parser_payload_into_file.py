#!/usr/local/bin/python2.7
import tempfile
import dpkt
from dpkt.utils import mac_to_str, inet_to_str
import time
import hashlib
import subprocess


pcap_file='dtn4.pcap'
started = False
SEPARATOR = "<SEPARATOR>"
cur_seq = 0
counter = 0
def handle_pkt(packet):
    global f2
    global started
    global file_hash
    global f3
    if SEPARATOR in str(packet) and not started :
        started = True
        setir2 = packet.decode()
        filename,filesize = setir2.split(SEPARATOR)
        f2= tempfile.NamedTemporaryFile()
        file_hash = hashlib.md5()
        f3 = open(filename,'wb')
        print("Filename = {} , filesize = {} ".format(filename,filesize))
        started = True
        return
    if started and packet != "" :
        file_hash.update(packet)
        f3.write(packet)


print("Starting ")
#subprocess.call(['sh','./process3.sh'])
#subprocess.call(['sh','./process5.sh'])
#print("Got the needed stream from file ")


f = open(pcap_file,'rb')
pcap = dpkt.pcap.Reader(f)

for _, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)

    if not isinstance(eth.data,dpkt.ip.IP):
        #print("NOT IP Packet")
        continue

    ip = eth.data

    if isinstance(ip.data, dpkt.tcp.TCP):
        if inet_to_str(ip.src)!='192.168.1.2' :
            continue
        tcp = ip.data
        counter = counter + 1
        seq_num = tcp.seq
        payload = bytes(ip.data)
        print("counter = {}, seq_num = {}, Len = {}, cur_seq = {} ,  Payload = {} ".format(counter,seq_num,ip.len,cur_seq,payload))
        #if seq_num > cur_seq and 
        if payload[32:] != b'' and seq_num >=cur_seq :
            if cur_seq == 0 :
                cur_seq = tcp.seq
            else :
                cur_seq = seq_num + ip.len - 52
            handle_pkt(payload[32:])
        else :
            print("Dropped ",counter)

print("Final Hash = {},".format(file_hash.hexdigest()))
f2.close()
f.close()
