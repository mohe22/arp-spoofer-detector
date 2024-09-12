import logging
from scapy.all import ARP, sniff, Ether, IP, TCP, srp1 # type: ignore
import time
import threading

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("arp_spoofing_detector.log"),
        logging.StreamHandler()
    ]
)

class ARPSpoofingDetector:
    def __init__(self, TrustIpMac={}, alert_interval=0, verification_interval=60, ARPcounter_interval=60):
        self.ip_info = TrustIpMac
        self.last_alert_time = 0
        self.alert_interval = alert_interval
        self.last_verification_time = time.time()
        self.verification_interval = verification_interval
        self.ARPcounter_interval = ARPcounter_interval
        self.lock = threading.Lock() 
    def print_arp_counters_periodically(self):
        if len(self.ip_info) == 0:
            return
        else:
            try:
                while True:
                    with self.lock:  
                        logging.info("[*] ARP Counters:")
                        for ip, info in list(self.ip_info.items()):
                            if(info.get("ARP counter", 0) >= 25 ):
                                logging.warning(f"Suspicious activity detected: IP {ip} has {info.get('ARP counter', 0)} ARP requests.")
                            self.ip_info[ip]["ARP counter"] = 0
                            logging.info(f"\tIP: {ip}, ARP Counter: {info.get('ARP counter', 0)}")
                        logging.info("\t[*] Counters reset to 0")
                    time.sleep(self.ARPcounter_interval)
            except Exception as e:
                logging.error(f"Error in print_arp_counters_periodically: {e}")

    def verify_ip_mac_periodically(self):
        if len(self.ip_info) == 0:
            return
        else:
            try:
                while True:
                    current_time = time.time()
                    if current_time - self.last_verification_time >= self.verification_interval:
                        logging.info("[*] Verifying the IP-MAC table...")
                        with self.lock: 
                            for ip, info in list(self.ip_info.items()):
                                self.verify_ip_mac(ip, info['mac'])
                        self.last_verification_time = current_time
                    time.sleep(10)
            except Exception as e:
                logging.error(f"Error in verify_ip_mac_periodically: {e}")

    def detect_arp_spoofing(self, packet):
        try:
            current_time = time.time()
            if current_time - self.last_alert_time >= self.alert_interval:
                if packet.haslayer(ARP):
                    arp_packet = packet[ARP]
                    eth_packet = packet[Ether]
                    ip = arp_packet.psrc
                    mac = arp_packet.hwsrc

                    if arp_packet.op == 2:
                        logging.info("ARP response from IP: %s with MAC: %s" % (ip, mac))
                        if eth_packet.src != mac:
                            logging.warning(f"Ethernet source MAC {eth_packet.src} does not match ARP source MAC {mac}. Possible spoofing detected.")
                        if eth_packet.dst != arp_packet.hwdst:
                            logging.warning(f"Ethernet destination MAC {eth_packet.dst} does not match ARP destination MAC {arp_packet.hwdst}. Possible spoofing detected.")

                        with self.lock:  # Acquire the lock
                            if ip in self.ip_info:
                                self.ip_info[ip]["ARP counter"] += 1
                                if self.ip_info[ip]['mac'] != mac:
                                    logging.warning(f"ARP Spoofing Detected: IP {ip} is being used by multiple MAC addresses.")
                                    logging.warning(f"Previous MAC: {self.ip_info[ip]['mac']}, New MAC: {mac}")
                                    self.verify_ip_mac(ip, mac)
                                else:
                                    logging.info(f"ARP Reply: IP {ip} has MAC {mac}")
                            else:
                                if mac in [info['mac'] for info in self.ip_info.values()]:
                                    logging.warning(f"MAC address {mac} is already associated with another IP address.")
                                    self.verify_ip_mac(ip, mac)
                                else:
                                    self.verify_ip_mac(ip, mac)
                    elif arp_packet.op == 1:
                        with self.lock:  # Acquire the lock
                            if ip in self.ip_info:
                                self.ip_info[ip]["ARP counter"] += 1
                        logging.info(f"ARP Request: IP {arp_packet.psrc} is asking for MAC address of {arp_packet.pdst}")
                self.last_alert_time = current_time
        except Exception as e:
            logging.error(f"Error in detect_arp_spoofing: {e}");

    def verify_ip_mac(self, ip, mac):
        try:
            ip_packet = IP(dst=ip)
            tcp_syn = TCP(sport=40508, dport=40508, flags="S", seq=12345,)
            ether_frame = Ether(dst=mac)
            response = srp1(ether_frame / ip_packet / tcp_syn, verbose=False, timeout=2, iface="eth0")
            if not response:
                logging.error(f"Alarm: No TCP ACK received for IP {ip} with MAC {mac}. Possible spoofing detected. or was blocked by the firewall.")
                with self.lock:  # Acquire the lock
                    if ip in self.ip_info:
                        del self.ip_info[ip]
                        logging.info(f"Removed old association: IP {ip} -> MAC {mac}")
                        logging.info("New ARP table: %s", self.ip_info)
                return True
            else:
                logging.info("[*] Verifiyed IP-MAC association. TCP ACK received for IP: %s with MAC: %s" % (ip, mac))
                return False
        except Exception as e:
            logging.error(f"Error in verify_ip_mac: {e}")

    def start_sniffing(self):
        logging.info("Starting ARP Spoofing Detection...")
        sniff(prn=self.detect_arp_spoofing, filter="arp", store=0)

if __name__ == "__main__":
    TrustIpMac = {    }
    alert_interval = 15  # Customize the alert interval
    verification_interval = 120  # Customize the verification interval
    ARPcounter_interval = 120  # Customize the ARP counter reset interval

    detector = ARPSpoofingDetector(TrustIpMac, alert_interval, verification_interval, ARPcounter_interval)

    sniffing_thread = threading.Thread(target=detector.start_sniffing)
    sniffing_thread.start()

    verification_thread = threading.Thread(target=detector.verify_ip_mac_periodically)
    verification_thread.start()

    print_thread = threading.Thread(target=detector.print_arp_counters_periodically)
    print_thread.start()

    sniffing_thread.join()
    verification_thread.join()
    print_thread.join()
