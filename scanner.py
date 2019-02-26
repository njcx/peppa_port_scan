# -*- coding: utf-8 -*-

import argparse
import re
import time
import threading
from scapy.all import *

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)


class Discovery_Scan(object):
    '''
    说明:用于发现扫描
    '''

    def __init__(self,args,timeout=0.5,retry=0):
        self.targets = parse_target(args)
        self.timeout = timeout
        self.retry = retry

    def arp_scan(self,pdst):
        #ARP发现扫描
        ans = sr1(ARP(pdst=pdst),timeout=self.timeout,retry=self.retry,verbose=False)
        if ans:
            if ans[ARP].op == 2:    #操作码为2是is-at，是ARP响应
                print '[+]IP: %s => MAC: %s' % (pdst,ans[ARP].hwsrc)

    def icmp_scan(self,dst):
        #ICMP发现扫描
        ans = sr1(IP(dst=dst)/ICMP(),timeout=self.timeout,retry=self.retry,verbose=False)
        if ans:
            if ans[ICMP].type == 0: #ICMP type为0表示是ICMP echo-reply
                print '[+]IP:主机%s echo-reply.' % dst

    tcp_info = {}
    def tcp_scan(self,dst,port):
        #TCP SYN,发送TCP SYN包，有响应表示端口开放
        ans,unans = sr(IP(dst=dst)/TCP(sport=RandShort(),dport=port,flags='S'),
                      timeout=self.timeout,retry=self.retry,verbose=False)
        if ans.res:
            if ans.res[0][0][IP].dst not in Discovery_Scan.tcp_info:
                Discovery_Scan.tcp_info[ans.res[0][0][IP].dst] = True

    udp_info = {}
    def udp_scan(self,dst,port):
        #UDP，发送UDP包，有响应表示端口开放
        ans,uans = sr(IP(dst=dst)/UDP(sport=RandShort(),dport=port),
                      timeout=self.timeout,retry=self.retry,verbose=False)
        if ans.res:
            if ans.res[0][0][IP].dst not in Discovery_Scan.udp_info:
                Discovery_Scan.udp_info[ans.res[0][0][IP].dst] = True

class Port_Scan(object):
    '''
    说明:用于进行端口扫描，判断端口是否开放
    '''
    def __init__(self,args,timeout=0.5,retry=0):
        self.targets = parse_target(args)
        self.timeout = timeout
        self.retry = retry

    syn_port_dict = {}
    def syn_port_scan(self,dst,port):
        #TCP SYN端口扫描，若SYN包返回携带SYN、ACK（即TCP.flags=18）标志的包，则表明此端口打开。
        ans,uans = sr(IP(dst=dst)/TCP(sport=RandShort(),dport=port,flags='S'),
                      timeout=self.timeout,retry=self.retry,verbose=False)
        if ans:
            first_respons_pkt = ans.res[0][1]
            if first_respons_pkt[TCP] and first_respons_pkt[TCP].flags == 18:
                if first_respons_pkt[IP].src not in Port_Scan.syn_port_dict:
                    Port_Scan.syn_port_dict[first_respons_pkt[IP].src] = [first_respons_pkt[TCP].sport]
                else:
                    Port_Scan.syn_port_dict[first_respons_pkt[IP].src].append(first_respons_pkt[TCP].sport)

    udp_port_dict = {}
    def udp_port_scan(self,dst,port):
        #UDP端口扫描，若UDP端口返回ICMP port-unreachable,则表示端口打开。（排除某些主机对任何UDP端口的探测都响应为ICMP port-unrechable）
        ans,uans = sr(IP(dst=dst)/UDP(sport=RandShort(),dport=port),
                      timeout=self.timeout, retry=self.retry, verbose=False)
        if ans.res and ans.res[0][1].haslayer(UDPerror):
            first_respons_pkt = ans.res[0][1]
            if first_respons_pkt[IP].src not in Port_Scan.udp_port_dict:
                Port_Scan.udp_port_dict[first_respons_pkt[IP].src] = [first_respons_pkt[UDPerror].dport]
            else:
                Port_Scan.udp_port_dict[first_respons_pkt[IP].src].append(first_respons_pkt[UDPerror].dport)

def parse_opt():
    '''
    @说明：通过argparse模块解析程序传入的参数
    @return:args
    '''
    usage = 'python %(prog)s <-p ping扫描类型> <-s 端口发现类型> [-t target] [--port ports]'
    description = '简单扫描工具，可以进行存活扫描及端口扫描.\n' \
                  '存活扫描包括：ARP扫描、ICMP扫描、TCP扫描、UDP扫描.\n' \
                  '端口扫描包括：TCP SYN扫描、TCP ACK扫描、TCP FIN扫描.'
    epilog = '以上做为说明，祝好运！'
    parser = argparse.ArgumentParser(usage=usage,description=description,epilog=epilog,version='v1.0')

    target_group = parser.add_argument_group('target group',description='用于设置IP、PORT参数')
    target_group.add_argument('--target',dest='target',action='store',
                              help='target为IP或IP段，如192.168.1.1，192.168.1.x，或192.168.1.1-254')
    target_group.add_argument('--port',dest='port',action='store',
                              help='port为待扫描的端口，如21,80,...或21-80')

    ping_group = parser.add_argument_group('ping group',description='用于开启存活扫描相关选项')
    ping_group.add_argument('-p',dest='ping',action='store_true',help='开启存活扫描')
    ping_group.add_argument('--ARP',dest='ARP',action='store_true',help='启动ARP扫描')
    ping_group.add_argument('--ICMP',dest='ICMP',action='store_true',help='启动ICMP扫描')
    ping_group.add_argument('--TCP',dest='TCP',action='store_true',help='启动TCP扫描')
    ping_group.add_argument('--UDP',dest='UDP',action='store_true',help='启动UDP扫描')

    port_scan_group = parser.add_argument_group('port scan group',description='用于开启端口扫描相关选项')
    port_scan_group.add_argument('-s',dest='scan',action='store_true',help='开启端口扫描')
    port_scan_group.add_argument('--SYN',dest='SYN',action='store_true',help='开启SYN扫描')
    port_scan_group.add_argument('--ACK',dest='ACK',action='store_true',help='开启ACK扫描')
    port_scan_group.add_argument('--FIN',dest='FIN',action='store_true',help='开启FIN扫描')
    port_scan_group.add_argument('--UPORT', dest='UPORT', action='store_true', help='开启UDP端口扫描')

    utils_group = parser.add_argument_group('utils group',description='用于开启扫描过程中的一些实用选项')
    utils_group.add_argument('--timeout',dest='timeout',action='store',type=float,help='设置发包超时时间,默认0.5秒')
    utils_group.add_argument('--retry',dest='retry',action='store',type=int,help='设置发包重试次数，默认不重试')

    args = parser.parse_args()
    if not args.ping and not args.scan:
        print '[-]必须通过-p/-s选项开启一种扫描'
        print '\n'
        parser.print_help()
        exit(1)
    elif not args.target:
        print '[-]必须通过--target选项指定扫描的对象'
        print '\n'
        parser.print_help()
        exit(1)
    if args.ping:
        if not args.ARP and not args.ICMP and not args.TCP and not args.UDP:
            args.ICMP = True  #若没有指定任何ping扫描方式，则默认选择ICMP扫描
            print '[+]没有指定任何ping扫描方式，默认选择ICMP扫描'
    if args.scan:
        if not args.SYN and not args.ACK and not args.FIN and not args.UPORT:
            args.SYN = True  #若没有指定任何端口扫描方式，则默认选择SYN扫描
            print '[+]没有指定任何端口扫描方式，默认选择SYN扫描'
        if not args.port:
            args.port = '1-1024'    #若没有指定任何扫描端口，则默认扫描1-1024
            print '[+]没有指定任何扫描端口，默认扫描1-1024'

    return args

def parse_target(args):
    '''
    @说明：用于解析如'192.168.1.1，192.168.1.x，...或192.168.1.1-254'格式的IP为单独的IP，用于解析如'21,80,...或21-80'格式的端口为单独的端口
    @param: args,一个namespace对象
    @return: (ip_list,port_list)
    '''
    pattern1 = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    pattern2 = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$'
    pattern3 = r'\d{1,5}$'
    pattern4 = r'\d{1,5}-\d{1,5}$'
    ip_list,port_list = None,None
    if args.target:
        if re.search(pattern1,args.target):
            ip_list = args.target.split(',')
        elif re.match(pattern2,args.target):
            _split = args.target.split('-')
            first_ip = _split[0]
            ip_split = first_ip.split('.')
            ipdot4 = range(int(ip_split[3]), int(_split[1]) + 1)
            ip_list = [ip_split[0] + '.' + ip_split[1] + '.' + ip_split[2] + '.' + str(p) for p in ipdot4]
        else:
            print '[-]target格式输入有误，请查看帮助！'
            exit(1)
    if args.port:
        if re.match(pattern4,args.port):
            _split = args.port.split('-')
            port_list = range(int(_split[0]),int(_split[1])+1)
        elif re.search(pattern3,args.port):
            port_list = args.port.split(',')
        else:
            print '[-]port格式输入有误，请查看帮助！'
            exit(1)
    return ip_list,port_list


def main():
    '''
    @说明：扫描的主程序，首先根据条件创建Ping扫描或端口扫描对象，然后调用相关的扫描方法进行扫描。
    '''
    args = parse_opt()
    if args.ping: #是否启动Ping扫描
        if not args.timeout and not args.retry:
            obj_ping = Discovery_Scan(args)
        elif args.timeout and not args.retry:
            obj_ping = Discovery_Scan(args,timeout=args.timeout)
        elif not args.timeout and args.retry:
            obj_ping = Discovery_Scan(args,retry=args.retry)
        else:
            obj_ping = Discovery_Scan(args,args.timeout,args.retry)
        ip_list = obj_ping.targets[0]
        if ip_list:
            #ARP扫描
            if args.ARP:
                for pdst in ip_list:
                    t = threading.Thread(target=obj_ping.arp_scan,args=(pdst,))
                    t.start()
                while threading.activeCount() != 1:    #避免线程还没有运行完就提前输出不全的结果
                    time.sleep(1)
            #ICMP扫描
            elif args.ICMP:
                for dst in ip_list:
                    t = threading.Thread(target=obj_ping.icmp_scan,args=(dst,))
                    t.start()
                while threading.activeCount() != 1:    #避免线程还没有运行完就提前输出不全的结果
                    time.sleep(1)
            #TCP扫描
            elif args.TCP:
                port_list = [80,443,21,22,23,25,53,135,139,137,445,1158,1433,1521,3306,3389,7001,8000,8080,9090]
                print '[+]请稍等，时间较长！'
                for dst in ip_list:
                    print '[!]扫描...',dst
                    for port in port_list:
                        t = threading.Thread(target=obj_ping.tcp_scan,args=(dst,port))
                        t.start()

                print '[+]正在处理扫描信息.'
                while threading.activeCount() != 1:    #避免线程还没有运行完就提前输出不全的结果
                    time.sleep(1)

                if not obj_ping.tcp_info:
                    print '\n'
                    print '=' * 20
                    print '[+]未发现在线主机.'
                else:
                    print '\n'
                    print '=' * 20
                    for ip_a in sorted(obj_ping.tcp_info.keys()):
                        print '[+]主机 %s 在线.' % ip_a
            #UDP扫描
            elif args.UDP:
                port_list = [7,9.13,15,37,53,67,68,69,135,137,138,139,445,520]
                print '[+]请稍等，时间较长！'
                for dst in ip_list:
                    print '[!]扫描...',dst
                    for port in port_list:
                        t = threading.Thread(target=obj_ping.udp_scan,args=(dst,port))
                        t.start()

                print '[+]正在处理扫描信息.'
                while threading.activeCount() != 1:    #避免线程还没有运行完就提前输出不全的结果
                    time.sleep(1)

                if not obj_ping.udp_info:
                    print '\n'
                    print '=' * 20
                    print '[+]未发现在线主机.'
                else:
                    print '\n'
                    print '=' * 20
                    for ip_a in sorted(obj_ping.udp_info.keys()):
                        print '[+]主机 %s 在线.' % ip_a
    if args.scan:  #是否启动端口扫描
        if not args.timeout and not args.retry:
            obj_port = Port_Scan(args)
        elif args.timeout and not args.retry:
            obj_port = Port_Scan(args,timeout=args.timeout)
        elif not args.timeout and args.retry:
            obj_port = Port_Scan(args,retry=args.retry)
        else:
            obj_port = Port_Scan(args,args.timeout,args.retry)

        ip_list,port_list = obj_port.targets
        if ip_list and port_list:
            if args.SYN:
                for dst in ip_list:
                    print '[!]扫描...',dst
                    for port in port_list:
                        t = threading.Thread(target=obj_port.syn_port_scan,args=(dst,int(port)))
                        t.start()

                print '[+]正在处理扫描信息.'
                while threading.activeCount() != 1:    #避免线程还没有运行完就提前输出不全的结果
                    time.sleep(1)

                if not obj_port.syn_port_dict:
                    print '\n'
                    print '=' * 20
                    print '[+]未发现开放TCP端口.'
                else:
                    print '\n'
                    print '=' * 20
                    for k,v in obj_port.syn_port_dict.items():
                        print '[+]主机 %s 开放的TCP端口有：%s' % (k,str(v))
            elif args.ACK:
                pass    #基本不能使用
            elif args.FIN:
                pass    #基本不能使用
            elif args.UPORT:
                for dst in ip_list:
                    print '[!]扫描...',dst
                    for port in port_list:
                        t = threading.Thread(target=obj_port.udp_port_scan,args=(dst,int(port)))
                        t.start()

                print '[+]正在处理扫描信息.'
                while threading.activeCount() != 1:    #避免线程还没有运行完就提前输出不全的结果
                    time.sleep(1)

                if not obj_port.udp_port_dict:
                    print '\n'
                    print '=' * 20
                    print '[+]未发现开放UDP端口.'
                else:
                    print '\n'
                    print '=' * 20
                    for k,v in obj_port.udp_port_dict.items():
                        print '[+]主机 %s 开放的UDP端口有：%s' % (k,str(v))


if __name__ == '__main__':
    try:
        start_time = time.time()
        main()
        stop_time = time.time()
        print '[+]总共耗时'+str(stop_time-start_time)+'秒.'
    except Exception,e:
        print '[-]执行出错，具体错误见下面信息.'
        print e