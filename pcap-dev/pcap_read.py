# -*- coding: utf-8 -*-

import sys
import socket
from datetime import datetime,timedelta
import gc

import pcap
import dpkt
from dpkt.compat import compat_ord

PCAP_DATALINK_RAW = 101
decoders = {
    dpkt.pcap.DLT_NULL: dpkt.loopback.Loopback,
    dpkt.pcap.DLT_LOOP: dpkt.loopback.Loopback,
    dpkt.pcap.DLT_LINUX_SLL: dpkt.sll.SLL,
    dpkt.pcap.DLT_EN10MB: dpkt.ethernet.Ethernet,
    dpkt.pcap.DLT_RAW: dpkt.ip.IP,
    PCAP_DATALINK_RAW: dpkt.ip.IP
}

def get_pkts_from_pcaps(pcap):
    if not pcap:
        return None
    
    decoder = decoders.get(pcap.datalink())
    pcaps = []
    for ts, buf in pcap:
        eth = decoder(buf)
        
        if pcap.datalink() == PCAP_DATALINK_RAW:
            ipdata = eth
        elif isinstance(eth.data, dpkt.ip.IP):
            ipdata = eth.data
        
        pcaps.append(ipdata)
    return pcaps


def deal_pkts_from_pcap(pcapfile, callback, *args):
    with open(pcapfile, 'rb') as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except Exception as err:
            print(err)
            pcap = dpkt.pcapng.Reader(f)
        
        if not args:
            return callback(pcap)
        else:
            return callback(pcap, args)

def pkt_extractor_by_dpkt(pkt):
    '''Extract packet by dpkt'''

    def inet_to_str(inet):
    """Convert inet object to a string"""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

    ip = pkt
    #tm_hdr = "[%6s] " % p[0]
    tm_hdr = str(datetime.utcfromtimestamp(p[0]))
    
    if not isinstance(ip, dpkt.ip.IP):
        printLog('[pktsdump] Non IP Packet type not supported %s\n' % ip.__class__.__name__)
        return tm_hdr, "Unknow"
    
    df = bool(ip.off & dpkt.ip.IP_DF)
    mf = bool(ip.off & dpkt.ip.IP_MF)
    off = ip.off & dpkt.ip.IP_OFFMASK
    ip_hdr = "IP: %s > %s  (ttl=%d DF=%d MF=%d offset=%d)" % \
        (inet_to_str(ip.src), inet_to_str(ip.dst), ip.ttl, df, mf, off)
    id_hdr = "[ip.id=%d ip.len=%d]" % (ip.id, ip.len)
    
    data_hdr = "Unknow"
    if isinstance(ip.data, dpkt.icmp.ICMP):
        icmp = ip.data
        data_hdr = "ICMP: %s > %s (type:%d code:%d id:%d)" % (inet_to_str(ip.src), 
            inet_to_str(ip.dst), icmp.type, icmp.code, icmp.data.id)
    elif isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        data_hdr = "TCP: %s:%d > %s:%d (seq:%d ack:%d flags:%d win;%d)" % (inet_to_str(ip.src),
            tcp.sport, inet_to_str(ip.dst), tcp.dport, tcp.seq, tcp.ack, tcp.flags, tcp.win)
    elif isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        data_hdr = "UDP: %s:%d > %s:%d ulen:%d" % (inet_to_str(ip.src), udp.sport, 
            inet_to_str(ip.dst), udp.dport, udp.ulen)
    else:
        printLog('[pktsdump] Unsupport Protocal In Transparent Layer\n')
        data_hdr = ip_hdr
    
    return ' '.join((tm_hdr, id_hdr, data_hdr))

def test_deal_pcaps():
    def cb(pcap):
        pcaps = get_pkts_from_pcaps(pcap)
        for p in pcaps:
            pkt_extractor_by_dpkt(p):


    deal_pkts_from_pcap("./test.pcap", cb)

if __name__ == "__main__":
    test_sniff_by_dpkt()
    test_wrpcap_by_dpkt()