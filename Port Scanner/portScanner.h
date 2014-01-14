#include <stdio.h> 
//memset, strcpy, etc..
#include <string.h>
//for cout, cin
#include <iostream> 
//to exit the program gracefully...[exit(0)];
#include <stdlib.h> 
#include <sys/socket.h>
//to report error numbers
#include <errno.h> 
//to incorporate pthread functionality
#include <pthread.h>
//for internet operations such as htons, ntohs, etc...
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
//Provides declarations for tcp header
#include <netinet/tcp.h>
//Provides declarations for ip header
#include <netinet/ip.h>	
#include <netinet/udp.h>	
//for random number generator
#include <time.h>
//for using string in cpp
#include <string>
//include pcap
#include <pcap.h>
#include <time.h>
#include <ifaddrs.h>
//Provides declarations for icmp header
#include <netinet/ip_icmp.h> 
#include <queue>
#include <netdb.h>
#include <algorithm>
#include <iomanip>
#include <sys/poll.h>


#include <iostream>
#include <fstream>
#include <getopt.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <math.h>
#include <queue>
#include <pthread.h>
#include <signal.h>
using namespace std;



//------------------------------------------------------------------
//declarations for all functions used
void readCommandLineArg(int argc, char* argv[]);
void printHelpScreen();
void resolveIpArguments(char* optarg2);
void resolvePortArguments(char* optarg1);
void resolvecsPortArguments(char* optarg1);
void resolveFileArguments(char* optarg);
void resolvePrefixArguments(char* optarg2);
void resolveIpArguments(char* optarg2);
void assignIpAddress(int currentIp[4], int* resultantIp);
void calculatePrefix(int prefixVal,char* ipVal);
void calculateBinary(char* seperatedIpValue);
void scanPorts(int port, char* ip_addresses);
void printAllArguments();




void* worker_thread(void* arg);

pthread_mutex_t mutex_main;
pthread_mutex_t mutex_service_name_tcp;
pthread_mutex_t mutex_service_name_udp;
pthread_mutex_t mutex_processed_job;
/*struct jobs{
string all_ip;
int all_ports;
string scans;
};*/

struct jobs
{
	string all_ip;
	int all_ports;
	string scans;
	//for processing scans and storing result
	string syn_scan;
	string ack_scan;
	string null_scan;
	string fin_scan;
	string xmas_scan;
	string udp_scan;
	//service names
	string service_name;
	//string version_number;	
	string conclusion;
};



jobs j;
jobs temp_job;
jobs temp_job_new;
int speed_up;
//stores all combinations of ports and ips
queue<jobs> all_ips;

//stores all jobs needed for multithreading
queue<jobs> all_scans;
//vector<jobs> all_jobs;
//declaration of further functions
void resolveScanArguments(queue<jobs> all_ips,string a1,string a2);
void populateMultiThreadQueue(queue<jobs> all_ips, string scanType);

struct arguments
{
char* ip_addresses;
int prefix;
int port;
int range_ports[65535];
int range_cs_ports[65535];
const char* x;
char* y;
};

arguments a;

string scans1;
string scans2 = "SYN,ACK,NULL,FIN,XMAS,UDP";

//stores all scan techniques for printing
string all_s[6];

int scanFlag = 0; //if set then user specified scans exist
int singlePortFlag = 0; //if set then only a there exists only a single port to scan
int rangePortsFlag = 0; //if set then a range of ports need to be scanned
int csPortsFlag = 0; //if set then various ports comma separated need to be scanned
int ipFileFlag = 0; //if set then ip and prefix values from a file need to be read
int p1 = 0; //counter for resolving ports
int p_num_cs = 0; //counter for resolving comma seperated ports
int range_cs_ports_counter = 0; //counter for resolving a range of ports
int p_num_range = 0; //counter for resolving a range of ports
int num = 0; //counter for printing all scans specified by user
string printingScans1[6]; //stores scans specified by use

//-----------------------------------------------------------------

//declaring functions
void createIpHeader(struct iphdr* ip_header, struct sockaddr_in destination_addr, int transport_layer_prot);

void createTCPHeader(struct tcphdr* tcp_header, int source_port, int destination_port, int scan_technique);
void createPseudoHeader(struct pseudo_hdr *pseudo_header, struct tcphdr* tcp_header, struct iphdr *ip_header, int transport_layer_prot);

void createUDPHeader(struct udphdr *udp_header, int source_port, int destination_port);
void createPseudoHeader_UDP(struct pseudo_hdr_udp *pseudo_header, struct udphdr* udp_header, struct iphdr *ip_header, int transport_layer_prot, char payload[4096]);

long calculateChecksum(unsigned short * headerAddr, int header_length);
string get_ip(char * buffer);

int tcp_udp_scan(struct jobs job);
int send_receive_tcp_packets(int sd, char *payload, sockaddr_in destination_addr, int retry_value, struct jobs job, jobs * processed_job);
int send_receive_udp_packets(int sd, char *payload, sockaddr_in destination_addr, int retry_value, struct jobs job, jobs * processed_job, int payload_length);


void ssh_scan(sockaddr_in destination_addr, struct jobs * job);
void imap_scan(sockaddr_in destination_addr, struct jobs * job);
void smtp_scan(sockaddr_in destination_addr, struct jobs * job);
void pop_scan(sockaddr_in destination_addr, struct jobs * job);
void whois_scan(sockaddr_in destination_addr, struct jobs * job);
//void http_scan(sockaddr_in destination_addr, char * version_number);
void http_scan(sockaddr_in destination_addr, struct jobs * job);

void output();
void print_headers();
void draw_conclusions();
void consolidate_jobs();
void print_results(string ip_address, int status);

//void create_dns_packet(sockaddr_in destination_addr, dns_header dns);
void create_dns_packet(jobs job);







//to calculate the checksum 
struct pseudo_hdr
{
	unsigned int source_addr;
	unsigned int destination_addr;
	unsigned char zeros;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;	
};

struct pseudo_hdr_udp
{
	unsigned int source_addr;
	unsigned int destination_addr;
	unsigned char zeros;
	unsigned char protocol;
	unsigned short udp_length;

	struct udphdr udp;	
};
///////////////////////////////////////////////////////////

struct dns_header
{
unsigned short id;       // identification number
unsigned char rd;     // recursion desired
unsigned char tc;     // truncated message
unsigned char aa;     // authoritive answer
unsigned char opcode; // purpose of message
unsigned char qr;     // query/response flag
unsigned char rcode;  // response code
unsigned char cd;     // checking disabled
unsigned char ad;     // authenticated data
unsigned char z;      // its z! reserved
unsigned char ra;     // recursion available
unsigned short q_count;  // number of question entries
unsigned short ans_count; // number of answer entries
unsigned short auth_count; // number of authority entries
unsigned short add_count; 
};

struct dns_question
{
unsigned short qtype;
unsigned short qclass;
};

struct dns_r_data
{
unsigned short type;
unsigned short _class;
unsigned int ttl;
unsigned short data_len;
};

struct dns_rr
{
unsigned char *name;
dns_r_data *resource;
unsigned char *rdata;
};
 
struct dns_query
{
unsigned char *name;
dns_question *ques;
};
//////////////////////////////////////////////////////////////////////////////////////////////////

//decalring global variables
char source_ip[20];
//struct in_addr destination_ip;
vector<jobs> all_processed_jobs;
vector<jobs> all_processed_jobs_final;
vector<jobs> processed_job_array_final;
//, "UDP"};
int all_s_size;




void createIpHeader(struct iphdr* ip_header, struct sockaddr_in destination_addr, int transport_layer_prot)
{
		//initialize the ip header with values
        ip_header -> ihl = 5;
        ip_header -> version = 4;
        ip_header -> tos = 0;        
        if(transport_layer_prot == 0)
        	ip_header -> tot_len = sizeof(struct ip) + sizeof(struct tcphdr);        
        else if (transport_layer_prot == 1)
        	ip_header -> tot_len = sizeof(struct ip) + sizeof(struct udphdr);        
        ip_header -> id = htons(66);
        ip_header -> frag_off = 0;
        ip_header -> ttl = 128;        
        if(transport_layer_prot == 0)
        	ip_header -> protocol = IPPROTO_TCP;
        else if (transport_layer_prot == 1)
        	ip_header -> protocol = IPPROTO_UDP;
        //No need to calculate the checksum of the ip header, the kernel will populate this field
        ip_header -> check = 0;             
        ip_header -> saddr = inet_addr (source_ip);                
		ip_header -> daddr = destination_addr.sin_addr.s_addr;
		//cout<<"Ip herader: "<<ip_header->protocol<<endl;
}


void createTCPHeader(struct tcphdr* tcp_header, int source_port, int destination_port, int scan_technique)
{
		//initialize the tcp header with values
        tcp_header -> source = htons(source_port);
        tcp_header -> dest = htons(destination_port);
        //seeding the rand function to start from the current time
		srand((time(NULL)));
	    //tcp_header -> seq = htonl(rand() % 65535);
	    tcp_header -> seq = htonl(98765);
        tcp_header -> ack_seq = 0;
        tcp_header -> doff = sizeof(struct tcphdr)/4;
        

        //setting the flags values depending on the scanning technique
        /*
        TCP HALF OPEN SYN SCAN---------0
		TCP NULL SCAN--------1
		TCP FIN SCAN---------2
		TCP XMAS SCAN--------3
		TCP ACK SCAN---------4		
        */

		if(scan_technique == 0)
		{
			
	    	tcp_header -> syn = 1;
	    	tcp_header -> fin = 0;
	    	tcp_header -> ack = 0;	
		}
		else if(scan_technique == 1)
		{
			tcp_header -> syn = 0;		
			tcp_header -> fin = 0;
	    	tcp_header -> ack = 0;
		}
		else if(scan_technique == 2)
		{
			tcp_header -> fin = 1;
			tcp_header -> syn = 0;	
	    	tcp_header -> ack = 0;
		}
		else if(scan_technique == 3)
		{
			tcp_header -> fin = 1;
			tcp_header -> psh = 1;
            tcp_header -> urg = 1;
		}
		else if(scan_technique == 4)
		{
			tcp_header -> ack = 1;
			tcp_header -> syn = 0;
	    	tcp_header -> fin = 0;
		}

		if (scan_technique != 3)
        {
                tcp_header -> psh = 0;
                tcp_header -> urg = 0;
        }        
        else if(scan_technique != 0 || scan_technique != 4)
        {
        	tcp_header -> syn = 0;		
	    	tcp_header -> ack = 0;
        }
        
        //populating other flags
        tcp_header -> rst = 0;               
        tcp_header -> window = 1460;
        tcp_header -> check = 0;        
        tcp_header -> urg_ptr = 0;
}


void createPseudoHeader(struct pseudo_hdr *pseudo_header, struct tcphdr* tcp_header, struct iphdr *ip_header, int transport_layer_prot)
{
		//initializing the pseudo header values 
		//populating from the ip header
        pseudo_header->source_addr = ip_header->saddr;
        pseudo_header->destination_addr = ip_header->daddr;
        pseudo_header->zeros = 0;
        if(transport_layer_prot == 0)
        	pseudo_header->protocol = IPPROTO_TCP;
        else if(transport_layer_prot == 1)
        	pseudo_header->protocol = IPPROTO_UDP;
        pseudo_header->tcp_length = htons( sizeof(struct tcphdr) );
        //copying the tcp header to the tcpheader field of the pseudo header field
        memcpy(&(pseudo_header->tcp) , tcp_header , sizeof (struct tcphdr));
        //calculating the checksum of the pseudo header and storing it in the checksum field of the tcp header
        tcp_header -> check = htons(calculateChecksum((unsigned short *)pseudo_header, sizeof(struct pseudo_hdr)));        
}

void createUDPHeader(struct udphdr *udp_header, int source_port, int destination_port)
{
	/* data */		
	//printf("here\n");
        udp_header -> source = htons(2145);
        
        udp_header -> dest = htons(destination_port);
        //udp_header -> len = htons(sizeof(struct udphdr) + payload);
        udp_header -> len = htons(sizeof(struct udphdr));
    	udp_header -> check = 0;
    //	printf("here after\n");
}

void createPseudoHeader_UDP(struct pseudo_hdr_udp *pseudo_header, struct udphdr* udp_header, struct iphdr *ip_header, int transport_layer_prot, char payload[4096])
{
		//initializing the pseudo header values 
		//populating from the ip header
        pseudo_header->source_addr = ip_header->saddr;
        pseudo_header->destination_addr = ip_header->daddr;
        pseudo_header->zeros = 0;
        pseudo_header->protocol = IPPROTO_UDP;
	    //pseudo_header->udp_length = htons( sizeof(struct udphdr) + strlen(payload));
        pseudo_header->udp_length = htons( sizeof(struct udphdr));// + strlen(payload));
        //copying the tcp header to the tcpheader field of the pseudo header field
        memcpy(&(pseudo_header->udp) , udp_header , sizeof (struct udphdr));
        //calculating the checksum of the pseudo header and storing it in the checksum field of the tcp header
        udp_header -> check = htons(calculateChecksum((unsigned short *)pseudo_header, sizeof(struct pseudo_hdr_udp)));        
}

long calculateChecksum(unsigned short * headerAddr, int header_length)
{
	int i;
	register long checkSum = 0;
	unsigned int temp_value;
	i = header_length;
	for (; i > 1;)
	{
		temp_value = htons(*headerAddr++);
		checkSum += temp_value;
		i -= 2;		
	}
	//handling odd length of the header
	if( header_length & 2 == 1)
	{
		checkSum += *(unsigned char *)headerAddr;
	}
	//adding the final carry, while it exists, to the checkSum value to 16 bits 
	while (checkSum >> 16)
	{
		checkSum = (checkSum & 0xffff) + (checkSum >> 16); 
	}
	checkSum = ~checkSum;	
	return checkSum;
	
}

void ssh_scan(sockaddr_in destination_addr, struct jobs * job)
{
	
	char request_buffer[1024];		
	strcpy(request_buffer,"");
    char reply_version[1024];
    memset(reply_version, '\0',1024);
    ssize_t sent_bytes;
       
	struct sockaddr_in sockaddr;
	
	sockaddr.sin_family= AF_INET;
	sockaddr.sin_addr.s_addr = destination_addr.sin_addr.s_addr;
	sockaddr.sin_port = htons(22);

	int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	//int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		
		struct timeval tv;
		tv.tv_sec = 5;  
		tv.tv_usec = 0; 

		setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
    
    if (connect(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1)
    {
    
    }
    else
    {
	   	sent_bytes = send(sd, request_buffer, strlen(request_buffer), 0);
       	recv(sd, reply_version, 200,0);        
       	int size = strlen(reply_version);
       	reply_version[size-2] = '\0';
       	//	cout<<"reply_Version: "<<reply_version;
       	//cout<<"New line character"<<endl;
       	job->service_name = job->service_name + " " + reply_version;
    }
    
}
void imap_scan(sockaddr_in destination_addr, struct jobs * job)
{
	char *version_number;
	//memset(version_number,'\0', 25);
	char request_buffer[1024];		
	strcpy(request_buffer,"\r\n");
    char reply_version[1024];
    memset(reply_version, '\0',1024);
    ssize_t sent_bytes;
       
	struct sockaddr_in sockaddr;
	
	sockaddr.sin_family= AF_INET;
	sockaddr.sin_addr.s_addr = destination_addr.sin_addr.s_addr;
	sockaddr.sin_port = htons(143);


	int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct timeval tv;

		tv.tv_sec = 5;  
		tv.tv_usec = 0; 

	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
    
    if (connect(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1)
    {
      	
    }
    else
    {
	   	sent_bytes = send(sd, request_buffer, strlen(request_buffer),0);
       	recv(sd, reply_version, 200,0);
        
        	
        recv(sd, reply_version, 200,0);               
        

	    char* temp;        		
        if((temp = strstr(reply_version,"IMAP")) != NULL)
        {

            temp[10] = '\0';            
            job->service_name =  job->service_name + " " + temp;        	
            
        }

        
    }
}
void smtp_scan(sockaddr_in destination_addr, struct jobs * job)
{
	char *version_number;
	//memset(version_number,'\0', 25);
	char request_buffer[1024];		
	strcpy(request_buffer,"");
    char reply_version[1024];
    memset(reply_version, '\0',1024);
    ssize_t sent_bytes;
       
	struct sockaddr_in sockaddr;
	//int sd = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr.sin_family= AF_INET;
	sockaddr.sin_addr.s_addr = destination_addr.sin_addr.s_addr;
	sockaddr.sin_port = htons(24);


	int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct timeval tv;

		tv.tv_sec = 5;  
		tv.tv_usec = 0; 

	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
	
    //cout<<"Status :"<< connect(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr));
    if (connect(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1)
    {
      	//perror("\n\t connect() failed \n");
    }
    else
    {
	   	send(sd, request_buffer, strlen(request_buffer),0);
        recv(sd, reply_version, 200,0);
        char* temp;        

        if((temp = strstr(reply_version,".com")) != NULL)
        {
       
            version_number = (char *)temp + strlen(".com") + 1;
             //cout<<"reply_version: "<<version_number<<endl;            
            temp[30] = '\0';            
            job->service_name = job->service_name + " " + version_number;
        }        
    }

}
void pop_scan(sockaddr_in destination_addr, struct jobs * job)
{
	char *version_number;
	//memset(version_number,'\0', 25);
	char request_buffer[1024];		
	strcpy(request_buffer,"\r\n");
    char reply_version[1024];
    memset(reply_version, '\0',1024);
    ssize_t sent_bytes;
       
	struct sockaddr_in sockaddr;
	
	sockaddr.sin_family= AF_INET;
	sockaddr.sin_addr.s_addr = destination_addr.sin_addr.s_addr;
	sockaddr.sin_port = htons(110);


	int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct timeval tv;

		tv.tv_sec = 5;  
		tv.tv_usec = 0; 

	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
    
    if (connect(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1)
    {
      	perror("\n\t connect() failed \n");
    }
    else
    {
	   	sent_bytes = send(sd, request_buffer, strlen(request_buffer),0);
       	recv(sd, reply_version, 200,0);
        char *pointer1 = strstr(reply_version, "+OK");                        

        if(pointer1 != NULL)
        {
        	strncpy(version_number, pointer1 + strlen("+OK") + 1, 7);
        }
    }
    job->service_name = job->service_name + " " + version_number;
    cout<<"";
}
void whois_scan(sockaddr_in destination_addr, struct jobs * job)
{	
	char *version_number;
	//memset(version_number,'\0', 25);
	char request_buffer[1024];		
	strcpy(request_buffer,"\r\n");
    char reply_version[1024];
    memset(reply_version, '\0',1024);
    ssize_t sent_bytes;
       
	struct sockaddr_in sockaddr;
	//int sd = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr.sin_family= AF_INET;
	sockaddr.sin_addr.s_addr = destination_addr.sin_addr.s_addr;
	sockaddr.sin_port = htons(43);


	int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct timeval tv;

		tv.tv_sec = 5;  
		tv.tv_usec = 0; 

	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

    if (connect(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1)
    {
      	
    }
    else
    {
	   	send(sd, request_buffer, strlen(request_buffer),0);
        recv(sd, reply_version, 200,0);
        char *pointer1 = strstr(reply_version, "Version");                                
        pointer1[13] = '\0';
        
        job->service_name = job->service_name + " " + pointer1;
        
    }
	
}

void http_scan(sockaddr_in destination_addr, struct jobs * job)
{	
	char request_buffer[1024];		
	strcpy(request_buffer,"HEAD / HTTP/1.1\r\n\r\n");
    char reply_version[1024];
    memset(reply_version, '\0',1024);
    ssize_t sent_bytes;
    
	struct sockaddr_in sockaddr;	
	sockaddr.sin_family= AF_INET;
	sockaddr.sin_addr.s_addr = destination_addr.sin_addr.s_addr;
	sockaddr.sin_port = htons(80);

	int sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		
		struct timeval tv;
		tv.tv_sec = 5;  
		tv.tv_usec = 0; 

	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

    if (connect(sd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1)
    {
      	//perror("\n\t connect() failed \n");
    }
    else
    {    	
	   	sent_bytes = send(sd, request_buffer, strlen(request_buffer),0);
        recv(sd, reply_version, 200,0);        
		//cout<<"response: "     <<reply_version<<endl;
        char* temp;        
        if((temp = strstr(reply_version,"Server:")) != NULL)
        {        	
        	//cout<<"temp"<<endl;
        	//cout<<temp<<endl;
        	char *ver = (char *)temp+strlen("Server:")+1;
          //  cout<<"Ver"<<endl;
        //cout<<temp<<endl;;           
            //strcpy(version_number,&ver);           
            //version_number = (char *) &ver;
            ver[23] = '\0';
           // printf("version_number:%s\n ", ver);
            //printf("herh: %s\n", version_number);
            job->service_name = job->service_name + " " + ver;
            return;
        }        
    }
        			
}