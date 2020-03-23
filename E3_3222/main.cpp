#define _CRT_SECURE_NO_WARNINGS
#define TRAFFIC_WARNING 1024*1024*1
#define INTERVAL 5
#include <WinSock2.h>
#include "pcap.h"
#include <iostream>
#include <fstream>
#include <conio.h>
using namespace std;
typedef struct ip_address{
	u_char byte[4];
}ip_address;
typedef struct mac_address{
	u_char byte[6];
};
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address saddr; // Source address 
	ip_address daddr; // Destination addres
	u_int	op_pad;			// Option + Padding
}ip_header;
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;
typedef struct mac_header
{
	mac_address dest_addr;
	mac_address src_addr;
	u_char type[2];
} mac_header;
typedef struct ip_mac_address
{
	ip_address ip; 
	mac_address mac;
}ip_mac_address;
class IPNode
{
private:
	ip_mac_address nodeAddress;
	long Len;
public:
	IPNode* pNext;
	IPNode(ip_mac_address Address)
	{
		nodeAddress = Address;
		Len = 0;
	}
	void addLen(long len)
	{
		Len += len;
	}
	long getLen()
	{
		return Len;
	}//返回IP地址
	ip_mac_address getAddress()
	{
		return nodeAddress;
	}

};
time_t beg;
class NodeList
{
	IPNode* pHead;
	IPNode* pTail;
public:
	NodeList(){
		pHead = pTail = NULL;
	}
	~NodeList(){
		if (pHead != NULL)
		{
			IPNode* pTemp = pHead;
			pHead = pHead->pNext;
			delete  pTemp;
		}
	}
	void addNode(ip_mac_address Address, long len){
		IPNode* pTemp;
		if (pHead == NULL){
			pTail = new IPNode(Address);
			pHead = pTail;
			pTail->pNext = NULL;
		}
		else{
			pTemp = pHead;
			while (true)
			{
				ip_mac_address tempAddress = pTemp->getAddress();
				bool flag = true;
				for (int i = 0; i < 6; i++)
					if (tempAddress.mac.byte[i] != Address.mac.byte[i])
						flag = false;
				for (int i = 0; i < 4; i++)
					if (tempAddress.ip.byte[i] != Address.ip.byte[i])
						flag = false;
				if (flag){
					pTemp->addLen(len);
					break;
				}
				if (pTemp->pNext == NULL){
					pTail->pNext = new IPNode(Address);
					pTail = pTail->pNext;
					pTail->addLen(len);
					pTail->pNext = NULL;
					break;
				}
				pTemp = pTemp->pNext;
			}
		}
	}
	void clearList()
	{
		IPNode* p, *q;
		p = pHead->pNext;
		while (p){
			q = p->pNext;
			free(p);
			p = q;
		}
		pHead = NULL;
	}
	ostream& print(ostream& os)
	{
		os <<"\n"<<INTERVAL<<" seconds\n";
		os << "MACaddress," << "IPaddress," << "Len\n";
		IPNode* pTemp = pHead;
		while (pTemp)
		{
			ip_mac_address lTemp = pTemp->getAddress();
			for (int i = 0; i < 5; i++) 
				os << hex << uppercase << int(lTemp.mac.byte[i]) << '-';
			os << hex << uppercase << int(lTemp.mac.byte[5]) << ',';
			for (int i = 0; i < 3; i++)
				os << dec << int(lTemp.ip.byte[i]) << '-';
			os << dec << int(lTemp.ip.byte[3]) << ',';
			os <<pTemp->getLen() << endl;
			pTemp = pTemp->pNext;
		}
		clearList();
		return os;
	}
};
NodeList sourceLink;
NodeList destLink;
long totalLen;
/* IPv4 header */

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

#define FROM_NIC
int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
#ifdef FROM_NIC
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1){
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next){
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0){
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i){
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB){
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0){
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0){
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	time(&beg); //current time           
	FILE* log;
	freopen_s(&log, "LogFile\\log.csv", "wb", stdout);
	printf("date,time,srcMAC,srcIP,destMAC,destIP,len\n");
	fclose(log);
	FILE* srcLog;
	freopen_s(&srcLog, "LogFile\\srcLog.csv", "wb", stdout);
	printf("srcLog\n");
	fclose(srcLog);
	FILE* destLog;
	freopen_s(&destLog, "LogFile\\destLog.csv", "wb", stdout);
	printf("destLog\n");
	fclose(destLog);
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

#else
	/* Open the capture file */
	if ((adhandle = pcap_open_offline("D:\File\Program\计算机网络\实验\实验03\E3\src\t2301.pcap", errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s.\n");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
#endif
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data){
	struct tm* ltime;
	char timestr[16];
	mac_header* mh;
	ip_header* ih;
	ip_mac_address sim;
	ip_mac_address dim;
	time_t local_tv_sec;
	int length = sizeof(mac_header) + sizeof(ip_header);
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));
	sim.ip = ih->saddr;
	sim.mac = mh->src_addr;
	dim.ip = ih->daddr;
	dim.mac = mh->dest_addr;

	/*输出到日志文件*/
	FILE* log;
	freopen_s(&log, "LogFile\\log.csv", "ab", stdout);
	printf("%d-%d-%d,", 1900 + ltime->tm_year, 1 + ltime->tm_mon, ltime->tm_mday);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	printf("%s,", timestr);
	for(int index = 0; index < 5; index++)
		printf("%02X-", mh->src_addr.byte[index]);
	printf("%02X,", mh->src_addr.byte[5]);
	for (int index = 0; index < 3; index++)
		printf("%d-", ih->saddr.byte[index]);
	printf("%d,", ih->saddr.byte[3]);
	for (int index = 0; index < 5; index++)
		printf("%02X-", mh->dest_addr.byte[index]);
	printf("%02X,", mh->dest_addr.byte[5]);
	for (int index = 0; index < 3; index++)
		printf("%d-", ih->daddr.byte[index]);
	printf("%d,", ih->daddr.byte[3]);
	printf("%d\n", header->len);
	sourceLink.addNode(sim, header->len);
	destLink.addNode(dim, header->len);

	/*超过阈值的收发记录，输出到显示器*/
	FILE *stds;
	freopen_s(&stds, "CON", "w", stdout);
	totalLen += header->len;
	if (totalLen >= TRAFFIC_WARNING)
		cout << "Warning:Traffic over "<<TRAFFIC_WARNING/1024/1024<<" MB!\n";

	if (local_tv_sec - beg >= INTERVAL){
		FILE* srcLog;
		freopen_s(&srcLog, "LogFile\\srcLog.csv", "ab", stdout);
		sourceLink.print(cout);
		FILE* destLog;
		freopen_s(&destLog, "LogFile\\destLog.csv", "ab", stdout);
		destLink.print(cout);
		fclose(srcLog);
		fclose(destLog);
		beg = local_tv_sec;
	}

	fclose(log);
	if ((_kbhit() && _getch() == 0x1b))
		exit(0);
}
