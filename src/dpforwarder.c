/*
 ============================================================================
 Name        : dpForwarder.c
 Author      : Royal Alice Academy of Sciences
 Version     :
 Copyright   : GPL V2.1
 Description : dpForwarder in C, Ansi-style
 ============================================================================
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

static unsigned short ip_cksum(unsigned short *addr, int len)
{
	unsigned short cksum;
	unsigned int sum = 0;

	while (len > 1)
	{
		sum += *addr++;
		len -= 2;
	}
	if (len == 1)
		sum += *(unsigned char*) addr;
	sum = (sum >> 16) + (sum & 0xffff);  //把高位的进位，加到低八位，其实是32位加法
	sum += (sum >> 16);  //add carry
	cksum = ~sum;   //取反
	return (cksum);
}

static unsigned short tcp_cksum(unsigned char *pkg_data)
{
	struct ip *iph = (struct ip *)pkg_data;
	struct tcphdr *tcph = (struct tcphdr *)(pkg_data + sizeof(struct ip));
	char tcpBuf[1500];

	struct pseudoTcpHeader
	{
	    unsigned int ip_src;
	    unsigned int ip_dst;
	    unsigned char zero;//always zero
	    unsigned char protocol;// = 6;//for tcp
	    unsigned short tcp_len;
	}psdh;

	psdh.ip_src = iph->ip_src.s_addr;
	psdh.ip_dst = iph->ip_dst.s_addr;
	psdh.zero = 0;
	psdh.protocol = IPPROTO_TCP;
	psdh.tcp_len = htons(ntohs(iph->ip_len) - sizeof(struct ip));

//	printf("ip_len:%d\n", ntohs((unsigned short)iph->ip_len));
//	printf("tcplen:%d\n", ntohs(psdh.tcp_len));
	memcpy(tcpBuf, &psdh, sizeof(struct pseudoTcpHeader));
	memcpy(tcpBuf+sizeof(struct pseudoTcpHeader), tcph, ntohs(psdh.tcp_len));

	return ip_cksum((unsigned short *)tcpBuf, sizeof(struct pseudoTcpHeader) + ntohs(psdh.tcp_len));
}

static unsigned short udp_cksum(unsigned char *pkg_data)
{
	struct ip *iph = (struct ip *)pkg_data;
	struct udphdr *udph = (struct udphdr *)(pkg_data + sizeof(struct ip));
	char udpBuf[1500];

	struct pseudoTcpHeader
	{
	    unsigned int ip_src;
	    unsigned int ip_dst;
	    unsigned char zero;//always zero
	    unsigned char protocol;//for udp
	    unsigned short udp_len;
	}psdh;

	psdh.ip_src = iph->ip_src.s_addr;
	psdh.ip_dst = iph->ip_dst.s_addr;
	psdh.zero = 0;
	psdh.protocol = IPPROTO_UDP;
	psdh.udp_len = htons(ntohs(iph->ip_len) - sizeof(struct ip));

//	printf("ip_len:%d\n", ntohs((unsigned short)iph->ip_len));
//	printf("tcplen:%d\n", ntohs(psdh.udp_len));
	memcpy(udpBuf, &psdh, sizeof(struct pseudoTcpHeader));
	memcpy(udpBuf+sizeof(struct pseudoTcpHeader), udph, ntohs(psdh.udp_len));

	return ip_cksum((unsigned short *)udpBuf, sizeof(struct pseudoTcpHeader) + ntohs(psdh.udp_len));
}

int main(int argc, char**argv)
{
	int sockfd, sockraw;
	struct sockaddr_in servaddr, srcaddr;
	socklen_t srcaddr_len;
	int n = 0;
	int total_len = 0;
	unsigned char pkg_data[4096];
	struct ip *iph = (struct ip *)pkg_data;
	struct tcphdr *tcph = (struct tcphdr *)(pkg_data + sizeof(struct ip));
	struct udphdr *udph = (struct udphdr *)(pkg_data + sizeof(struct ip));
	const int one = 1;
	char print_ip[16];

	if (argc != 2)
	{
		printf("usage:  dpforwarder <Port>\n");
		exit(1);
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1)
	{
		perror("socket(AF_INET,SOCK_DGRAM,0)\n");
		exit(1);
	}

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY );
	servaddr.sin_port = htons(atoi(argv[1]));
	if (bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) != 0)
	{
		perror("bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr))\n");
		exit(1);
	}

	sockraw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockraw == -1)
	{
		perror("socket(AF_INET, SOCK_RAW, IPPROTO_RAW)\n");
		exit(1);
	}

	if (setsockopt(sockraw, IPPROTO_IP, IP_HDRINCL, (char *) &one, sizeof(one))	== -1)
	{
		perror("setsockopt(sockraw, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one))\n");
		exit(1);
	}

	bzero(&srcaddr, sizeof(srcaddr));
	srcaddr.sin_family = AF_INET;

	for (;;)
	{
		srcaddr_len = sizeof(srcaddr);
		n = recvfrom(sockfd, pkg_data, 4096, 0, (struct sockaddr *) &srcaddr, &srcaddr_len);
		strcpy(print_ip, inet_ntoa(srcaddr.sin_addr));
		printf("forward packet, IP = %s, size = %d, total = %d KB\n", print_ip, n,
				(total_len += n) / 1024);

		strcpy(print_ip, inet_ntoa(iph->ip_src));
		printf("SIP = %s\n", print_ip);

		// IP checksum
		iph->ip_src = srcaddr.sin_addr;
		iph->ip_sum = 0;
		iph->ip_sum = ip_cksum((unsigned short *) pkg_data, 20);

		// tcp checksum
		switch (iph->ip_p)
		{
		case IPPROTO_TCP:
			tcph->check = 0; /* Checksum field has to be set to 0 before checksumming */
			tcph->check = tcp_cksum(pkg_data);
			break;
		case IPPROTO_UDP:
			udph->check = 0;
			udph->check = udp_cksum(pkg_data);
			break;
		}

		n = sendto(sockraw, pkg_data, n, 0, (struct sockaddr *) &srcaddr, sizeof(srcaddr));
	}
}


