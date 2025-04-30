import scapy.all as scapy
import sys
import time

stuff = {}

thing_counter = {}

last_time = time.time()

how_long = 60  
how_much = 10 

def syn_thing(pkt):
    if pkt.haslayer(scapy.TCP):
        if pkt[scapy.TCP].flags == "S":
            print("!!! SYN thingy from", pkt[scapy.IP].src, "to", pkt[scapy.IP].dst)

def ping_boom(pkt):
    if pkt.haslayer(scapy.ICMP):
        if pkt[scapy.ICMP].type == 8:
            print("!!! Pingy spam from", pkt[scapy.IP].src)

def xmas_thing(pkt):
    if pkt.haslayer(scapy.TCP):
        if pkt[scapy.TCP].flags == "FPU":
            print("!!! Xmas packet from", pkt[scapy.IP].src, "to", pkt[scapy.IP].dst)

def null_thing(pkt):
    if pkt.haslayer(scapy.TCP):
        if pkt[scapy.TCP].flags == 0:
            print("!!! NULL scan??", pkt[scapy.IP].src, "->", pkt[scapy.IP].dst)

def fin_boop(pkt):
    if pkt.haslayer(scapy.TCP):
        if pkt[scapy.TCP].flags == "F":
            print("!!! FIN boop from", pkt[scapy.IP].src)

def arp_weird(pkt):
    if pkt.haslayer(scapy.ARP):
        if pkt[scapy.ARP].op == 2:
            if pkt[scapy.ARP].psrc not in stuff:
                stuff[pkt[scapy.ARP].psrc] = pkt[scapy.ARP].hwsrc
            else:
                if stuff[pkt[scapy.ARP].psrc] != pkt[scapy.ARP].hwsrc:
                    print("!!! ARP trouble! IP", pkt[scapy.ARP].psrc, "spoofed by", pkt[scapy.ARP].hwsrc)

def port_go_brr(pkt):
    global last_time
    if pkt.haslayer(scapy.IP):
        who = pkt[scapy.IP].src
        now = time.time()

        if now - last_time > how_long:
            thing_counter.clear()

        if who not in thing_counter:
            thing_counter[who] = 1
        else:
            thing_counter[who] += 1

        if thing_counter[who] > how_much:
            print("!!! Port go BRRR from", who, "-", thing_counter[who], "times!")
            thing_counter[who] = 0

        last_time = now

def all_things(pkt):
    syn_thing(pkt)
    ping_boom(pkt)
    xmas_thing(pkt)
    null_thing(pkt)
    fin_boop(pkt)
    arp_weird(pkt)
    port_go_brr(pkt)

def sniffy_sniff(howmany):
    print("sniffing", howmany, "packets...")
    scapy.sniff(count=int(howmany), prn=all_things, store=0)

if __name__ == "__main__":
    print("""
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    ~    WELCOME TO D_IDS        ~
    ~     auther: dilshuppa      ~
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    attacks we look for:
     - syn boop
     - ping boom
     - xmas sparkle
     - null ghost
     - fin poke
     - arp liar
     - port brrrrr
    """)

    if len(sys.argv) != 2:
        print("yo, do this: python nop_ids.py <howmanypackets>")
        sys.exit(1)

    da_num = sys.argv[1]
    sniffy_sniff(da_num)
