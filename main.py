import locale
from dialog import Dialog
from os import getuid
from struct import *
import socket
def snfAnalyz(filters, ipProto, proto,d):
    def filtersCH(res):
        valid = 0
        if filters['port']['dst']:
            if filters['port']['dst'] == res['dst']['port']:
                valid = 1
            else:
                return 0
        if filters['port']['src']:
            if filters['port']['src'] == res['src']['port']:
                valid = 1
            else:
                return 0
        if filters['ip']['dst']:
            if filters['ip']['dst'] == res['dst']['ip']:
                valid = 1
            else:
                return 0
        if filters['ip']['src']:
            if filters['ip']['src'] == res['src']['ip']:
                valid = 1
            else:
                return 0
        return valid

    def Upack(proto, packet):
        packet, addr = sock.recvfrom(65565)
        ip_header = packet[0:20]
        iph = unpack('!BBHHHBBH4s4s', ip_header)
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        if proto == "tcp":
            UPformat = "!HHHHHHH"
            protoh = unpack(UPformat, packet[14:28])
            source_port = protoh[3]
            dest_port = protoh[4]
            return {"dst": {"port": dest_port, 'ip': s_addr}, 'src': {'port': source_port, 'ip': d_addr}}
        if proto == "udp":
            unpackFormat = "!HHHH"
            header = packet[0:8]
            protoh = unpack(unpackFormat, header)
            source_port = protoh[0]
            dest_port = protoh[1]
            return {"src": {"port": source_port, 'ip': s_addr}, 'dst': {'port': dest_port, 'ip': d_addr}}
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ipProto)
    count = 0
    while True:
        try:
            if filters:
                packet = sock.recv(60000)[0]
                res = Upack(proto, packet)
                count += filtersCH(res)
            else:
                sock.recv(60000)
                count += 1
            d.clear()
            d.infobox(f"        CTRL-C to exit\n\nMatch packet count : {count}")
        except KeyboardInterrupt:
            break   


def main():
    locale.setlocale(locale.LC_ALL, '')
    d = Dialog(dialog="dialog")
    d.set_background_title("eyeAnalyzer")
    if getuid():
        d.msgbox("This tool must be run in root mode !")
        d.clear()
        exit()
    proto= None
    filters = False
    while 1:
        code, tag = d.menu("[Menu]", choices=[
                           (" 1 ", "Start analysis"), (' 2 ', "Apply filters")], width=80)
        if not code == 'ok':
            code = d.yesno("Do you want to exit ?")
            if code == "ok":
                d.clear()
                exit()
        if tag == ' 1 ':
            d.clear()
            if proto:
                snfAnalyz(filters, socket.IPPROTO_TCP, proto,d)
            else :
                d.clear()
                d.msgbox("Please first specify the desired filter from the filters menu .")
        if tag == ' 2 ':
            while 1:
                d.clear()
                code, tag = d.menu("[Menu]", choices=[(' 1 ',"Enable / Disable filters"),(" 2 ", "Protocol"), (' 3 ', "Port"),(' 4 ', "IP"),(" 5 ","Exit")], width=80)
                if tag==' 1 ':
                    d.clear()
                    code, tag=d.menu("[Menu}",choices=[(' 1 ','Enable'),(' 2 ','Disable')])
                    if code=="ok" :
                        if tag==' 1 ':
                            filters={
                                'port': {
                                    'src': None,
                                    'dst': None
                                },
                                'ip': {
                                    'dst': None,
                                    'src': None
                                }
                            }
                        elif tag==' 2 ':
                            filters=False
            
                elif tag==" 2 ":
                    d.clear()
                    code, tag = d.menu("[Menu]", choices=[(" 1 ", "icmp"), (' 2 ', "tcp"),(' 3 ', "udp"),(" 4 ","Exit")], width=80)
                    if code=="ok" :
                        if tag==' 1 ':
                            proto='icmp'
                        elif tag==' 2 ':
                            proto='tcp'
                        elif tag==' 3 ':
                            proto='udp'
                        if not tag==' 4 ':    
                            d.clear()
                            d.msgbox(f"You will now only see {proto} packets")
                elif filters:
                    if tag==' 3 ':
                        d.clear()
                        code,tag=d.menu("[Menu]",choices=[(" 1 ","Source port"),(" 2 ","Destination port"),(" 3 ","Exit")])
                        if code=="ok" :
                            key=''
                            if tag==' 1 ':
                                key='src'
                            elif tag==' 2 ':
                                key='dst'
                            if not tag==' 3 ':
                                while 1:
                                    try:
                                        d.clear()
                                        code,data=d.inputbox(text="Enter the port number : ")
                                        data=int(data)
                                        if data<=65535:
                                            break
                                    except ValueError:
                                        pass
                                filters['port'][key]=data
                    elif tag==" 4 ":
                        d.clear()
                        code,tag=d.menu("[Menu]",choices=[(" 1 ","Source ip"),(" 2 ","Destination ip"),(" 3 ","Exit")])
                        if code=="ok" :
                            key=''
                            if tag==' 1 ':
                                key='src'
                            elif tag==' 2 ':
                                key='dst'
                            if not tag==' 3 ':
                                code,data=d.inputbox(text="Enter the ip : ")
                                filters['ip'][key]=data
                if tag==' 5 ':
                    break
main()
