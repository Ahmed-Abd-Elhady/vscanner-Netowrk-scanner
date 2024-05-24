import scapy.all as scapy
import optparse,datetime

#functions
def arp_send(range,extrct):
    arp_request = scapy.ARP(pdst=range)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast / arp_request
    answer =scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]
    for all in answer:
        print(f"{all[1].psrc}\t\t{all[1].hwsrc}")
    if extrct:
        with open('alive_ips.txt', 'w') as file:
            file.write('Ip Adress                Mac Adress\n')
            file.write("-------------------------------------------------------\n")
            for all in answer:
                file.write(f"{all[1].psrc}\t\t{all[1].hwsrc}\n")
            file.write(f"\nsave date : {datetime.datetime.now()}")
        print('\n[log] file saved')

def desgin():
    print('Ip Adress                Mac Adress')
    print(f"-------------------------------------------------------")



#arguments
parser = optparse.OptionParser()
parser.add_option("-r", "--range",dest="ip_range",help="range of ip scan")
parser.add_option("-l", "--fake_ip",dest="list",help="send packages with fake ip")
parser.add_option("--ex", "--extract",action="store_true",dest="extract",help="save alive hosts to txt file")
# parser.add_option("--t", "--time",action="store_true",dest="time",help="send packages with delay")

options, args= parser.parse_args()

if not options.ip_range and not options.list:
    parser.error("[log] -h for help")

if options.ip_range:
    desgin()
    arp_send(options.ip_range,options.extract)
elif options.list:
    print(f"[log] Start scan with file {options.list}....")
    desgin()
    with open(options.list,'r') as file:
        for line in file:
            arp_send(line.strip(),options.extract)







#scapy.ls(request)