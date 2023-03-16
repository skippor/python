# -*- coding: utf-8 -*-

import sys
import socket
from datetime import datetime,timedelta
import gc

# sys.path.append("/usr/local/lib/python/dpkt-1.9.2")
# sys.path.append("/usr/local/lib/python/pypcap-1.2.3")
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


def mac_addr(address):
    """Convert a MAC address to a readable/printable string"""
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    """Convert inet object to a string"""
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def pkt_extractor_by_dpkt(p):
    '''Extract packet by dpkt'''
    ip = p[1].data
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

def sniff_by_dpkt(filter, iface, timeout, count, promisc=False):
    '''sniff by dpkt: packets captured on interface `any` are cooked type'''
    def cb_sniff(ts, pkt, pkts):
        '''callback function for pcap.loop()'''
        pkts.append((ts, pkt))
        
    pkts = []
    try:
        #抓包默认关闭混杂模式
        sniffer = pcap.pcap(name=iface, promisc=promisc)
        
        if not filter is None:
            sniffer.setfilter(filter)
        #sniffer.loop(count, cb_sniff)
        
        decode = {
            pcap.DLT_NULL: dpkt.loopback.Loopback,
            pcap.DLT_LOOP: dpkt.loopback.Loopback,
            pcap.DLT_RAW: dpkt.ip.IP,
            pcap.DLT_LINUX_SLL: dpkt.sll.SLL,
            pcap.DLT_EN10MB: dpkt.ethernet.Ethernet
        }[sniffer.datalink()]
        
        cnt = 0
        deadline = datetime.now() + timedelta(seconds=timeout)
        for ptime,pdata in sniffer:
            #限制抓包时间和包个数
            if cnt >= count or deadline <= datetime.now():
                #sniffer.close()
                del sniffer
                gc.collect()
                break;
            pkts.append((ptime, decode(pdata)))
            cnt = cnt + 1
    except Exception as err:
        printLog("[pktsdump] sniff_by_dpkt failed: {0}".format(err))
    
    return pkts

def pkts_sniff(filter, iface, timeout, count, promisc=False):
    '''interface for monitor calling to dump packets'''
    return sniff_by_dpkt(filter=filter, iface=iface, timeout=timeout, count=count, promisc=promisc)

def pkts_save(filename, pkts, compress=False):
    '''save pcap data to file, which will compressed when option compress is True'''
    with open(filename,"wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=dpkt.pcap.DLT_LINUX_SLL)
        for ts,buf in pkts:
            if compress and (isinstance(buf.data.data, dpkt.tcp.TCP) or isinstance(buf.data.data, dpkt.udp.UDP)):
                buf.data.data.data = ""
        
            writer.writepkt(buf, ts=ts)
            f.flush()

def test_sniff_by_dpkt():
    print("test_sniff_by_dpkt begin")
    dpkts = sniff_by_dpkt(filter="icmp", iface="any", timeout=10, count=10)
    for pkt in dpkts:
        print(pkt_extractor_by_dpkt(pkt))
        
    print("test_sniff_by_dpkt exit")

def test_wrpcap_by_dpkt():
    print("test_wrpcap_by_dpkt begin")
    dpkts = sniff_by_dpkt(filter="icmp or tcp or udp", iface="any", timeout=100, count=100)
    pkts_save("./test_keepdata.pcap", dpkts)
    pkts_save("./test_compress.pcap", dpkts, compress=True)
    
    print("test_wrpcap_by_dpkt exit")


if __name__ == "__main__":
    test_sniff_by_dpkt()
    test_wrpcap_by_dpkt()