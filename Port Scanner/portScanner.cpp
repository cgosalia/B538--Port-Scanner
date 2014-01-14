/* =============================================================================================
Name : portScanner.cpp
Authors : Chintan Shailesh Gosalia <cgosalia@indiana.edu>, Awani Marathe <amarathe@indiana.edu>
Project: B538 - Project 4 : Port Scanner
================================================================================================
*/

#include "portScanner.h"
//string all_s[6] = {"ACK"};//,"FIN","XMAS", "NULL"};

int tcp_udp_scan(struct jobs job)
{	
	int result; 
	jobs processed_job;

	
	//initializing the buffer for datagrams
	char payload[4096];
	memset(payload, 0, 4096);	

	//Raw Socket Creation

    //create ip header    
    

	struct sockaddr_in destination_addr;
	destination_addr.sin_family = AF_INET;
    
    //destination address
    char temp_addr[16];
    int j;    
	for(j=0; j < job.all_ip.length(); j++)
	{
		temp_addr[j] = job.all_ip[j];
	}
	temp_addr[job.all_ip.length()] = '\0';	
	inet_pton(AF_INET, temp_addr, &destination_addr.sin_addr);	


//---------------------------------------------------------------------
	//char vversion_number[30];
	//memset(vversion_number,'\0',30);

    /*http_scan(destination_addr, (struct jobs *)&job);
    //printf("Version number: %s", vversion_number);
    /*cout<<"printing.."<<endl;
    cout<<"Veriosn numberin main: "<<job.service_name<<endl;
    exit(0);*/
    
	//---------------------------------------------------------------------
	//---------------------------------------------------------------------
	
	struct iphdr *ip_header = (struct iphdr*) payload;
	if(job.scans != "UDP")
	{
		
		
	    createIpHeader(ip_header, destination_addr, 0);
	}

    
    //create tcp header	
    
	if (job.scans == "UDP")
	{
		processed_job.all_ip = job.all_ip;
		processed_job.all_ports= job.all_ports;				
		char payload_buffer[1024];
		//memset(payload,0,1024);
		//createIpHeader(ip_header, destination_addr, 1);

		int sd_udp = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		//int sd_udp = socket (AF_INET, SOCK_RAW, IPPROTO_UDP);
    	if(sd_udp < 0)
    	{
        	//cout << "\nSocket creation unsuccessful. \nError number:" <<errno<< "\nError message :" <<strerror(errno)<< "\n";
        	return(0);
    	}
    	else
    	{
    		//cout<<"\nSocket creation successful.\n";
    	}
    	
		
		//jobs processed_job;
		//processed_job.all_ip = job.all_ip;
		//processed_job.all_ports= job.all_ports;

		//send tcp packets
		int result; 
		
		result = send_receive_udp_packets(sd_udp, payload, destination_addr, 0, job, (jobs *)&processed_job, strlen(payload_buffer));
		close(sd_udp);
		if(result == 0 && job.scans == "UDP")
		{
			processed_job.udp_scan = "UDP(Open|Filtered)";
			//cout<<processed_job.udp_scan<<endl;
		}

		//cout<<"Out of the send receive UDP sfunciton"<<endl;
	}
	else
	{
		int sd = socket (AF_INET, SOCK_RAW , IPPROTO_TCP);    
    	if(sd < 0)
    	{
        	//cout << "\nSocket creation unsuccessful. \nError number:" <<errno<< "\nError message :" <<strerror(errno)<< "\n";
        	return(0);
    	}
    	else
  		{
    		//cout<<"\nSocket creation successful`.\n";
    	}
		
		struct tcphdr* tcp_header = (struct tcphdr*) (payload + sizeof(struct ip));;
    	struct pseudo_hdr pseudo_header;

	    if(job.scans == "SYN")
	    	createTCPHeader(tcp_header, 2138, job.all_ports, 0);
	    else if(job.scans == "NULL")
	    	createTCPHeader(tcp_header, 2139, job.all_ports, 1); 
	    else if(job.scans == "FIN")
	    	createTCPHeader(tcp_header, 2140, job.all_ports, 2); 
	    else if(job.scans == "XMAS")
	    	createTCPHeader(tcp_header, 2141, job.all_ports, 3); 
	    else if(job.scans == "ACK")
	    	createTCPHeader(tcp_header, 2142, job.all_ports, 4); 

	    createPseudoHeader(&pseudo_header, tcp_header, ip_header, 0);    
	    //printf("psuedo done\n");

	    int sock_option_value = 1;
		int *tempPointer = &sock_option_value;
		if( setsockopt(sd, IPPROTO_IP, IP_HDRINCL, tempPointer, sizeof(sock_option_value)) < 0)
		{
			//cout<<"Set sock option failed."<<endl;
			return 0;
		}	
		else
		{
 				//cout<<"Socket created successfully"<<endl;
		}

		processed_job.all_ip = job.all_ip;
		processed_job.all_ports= job.all_ports;	

		//send tcp packets

		result = send_receive_tcp_packets(sd, payload, destination_addr, 0, job, &processed_job);

		if(result == 0 && job.scans == "SYN")
			processed_job.syn_scan = "SYN(Filtered)";
		if(result == 0 && job.scans == "ACK")
			processed_job.ack_scan = "ACK(Filtered)";
		if(result == 0 && job.scans == "NULL")
			processed_job.null_scan = "NULL(Open|Filtered)";
		if(result == 0 && job.scans == "FIN")
			processed_job.fin_scan = "FIN(Open|Filtered)";
		if(result == 0 && job.scans == "XMAS")
			processed_job.xmas_scan = "XMAS(Open|Filtered)";
		close(sd);
		
	}

//cout<<processed_job.udp_scan<<endl;
    if(job.all_ports<= 1024)
    {       	
	 
			struct servent *appl_name;
			if(job.scans != "UDP")
			{			
				char prot[4] = "TCP";
				pthread_mutex_lock(&mutex_service_name_tcp);
				appl_name =	getservbyport(htons(job.all_ports), prot);
				pthread_mutex_unlock(&mutex_service_name_tcp);
			}
			else if(job.scans == "UDP")
			{
				char prot[4] = "UDP";
				pthread_mutex_lock(&mutex_service_name_udp);
				appl_name =	getservbyport(htons(job.all_ports), prot);
				pthread_mutex_unlock(&mutex_service_name_udp);
			}
			if(appl_name != NULL)
				processed_job.service_name = appl_name->s_name;		

			}
			
			
			if(job.all_ports== 80)
    		{
    			http_scan(destination_addr, (struct jobs *)&processed_job);			
    			//cout<<"service_name: "<<processed_job.service_name<<endl;
    		//	exit(0);
    		}
    		else 
	    	if(job.all_ports== 22)
	    	{
	    		ssh_scan(destination_addr, (struct jobs *)&processed_job);			
	    		//processed_job.service_name = processed_job.service_name + " " + version_number;
	    	//	cout<<"service_name: "<<processed_job.service_name<<endl;
	    	//	exit(0);
	    	}
	    	else if(job.all_ports== 143)
	    	{
	    		//char * version_number;
	    		imap_scan(destination_addr, (struct jobs *)&processed_job);			
	    		//rocessed_job.service_name = processed_job.service_name + " " + version_number;
	    	//		cout<<"service_name: "<<processed_job.service_name<<endl;
	    	//		exit(0);
	    	}
	    	else if(job.all_ports== 24)
	    	{	    		
	    		smtp_scan(destination_addr, (struct jobs *)&processed_job);				    	
	    	//	cout<<"service_name: "<<processed_job.service_name<<endl;
	    	//	exit(0);
	    	}
	    	else if(job.all_ports== 110)
	    	{
	    		//char * version_number;
	    			cout<<endl;
	    		//fflush(stdout);
	    		pop_scan(destination_addr, (struct jobs *)&processed_job);			
	    		//processed_job.service_name = processed_job.service_name + " " + version_number;
	    	
	    	//		exit(0);
	    	}
	    	else if(job.all_ports== 43)
	    	{
	    		//char * version_number;
	    		whois_scan(destination_addr, (struct jobs *)&processed_job);			
	    		//processed_job.service_name = processed_job.service_name + " " + version_number;
	    	//	cout<<"service_name: "<<processed_job.service_name<<endl;
	    	//		exit(0);
	    	}
/*	cout<<"processed_job: "<<endl;*/
	//cout<<"here u are"<<endl;

/*	cout<<processed_job.service_name<<endl;
	cout<<processed_job.all_ip<<endl;
	cout<<processed_job.all_ports<<endl;
	cout<<processed_job.udp_scan<<endl;
*/
	//cout<<processed_job.syn_scan<<endl;
	//cout<<processed_job.ack_scan<<endl;
	//cout<<processed_job.xmas_scan<<endl;
	//cout<<processed_job.fin_scan<<endl;
	//cout<<processed_job.udp_scan<<endl;

	pthread_mutex_lock(&mutex_processed_job);
	all_processed_jobs.push_back(processed_job);			
	pthread_mutex_unlock(&mutex_processed_job);
	//cout<<"Size: "<<all_processed_jobs.size()<<endl;
}

int send_receive_tcp_packets(int sd, char *payload, sockaddr_in destination_addr, int retry_value, struct jobs job, jobs * processed_job)
{	
	if(retry_value >= 3)
	{
		close(sd);
		return 0;
	}

	int sentChars;
	if ((sentChars = sendto(sd, payload, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&destination_addr, sizeof(destination_addr))) < 0)	
    {
    //   cout<<"Attempt to send syn packet failed"<<endl;
    	close(sd);
        return 1;
    }
    

    char str_destination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(destination_addr.sin_addr), str_destination, INET_ADDRSTRLEN);	

    int sd1, sd2, r;	
    unsigned char *recv_buffer = (unsigned char *)malloc(65536);
    sd1 = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);     
    sd2 = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);     
    //saddr_size = sizeof(saddr);

    struct pollfd poll_fd1[2];
	poll_fd1[0].fd = sd1;
	poll_fd1[0].events = POLLIN;

	poll_fd1[1].fd = sd2;
	poll_fd1[1].events = POLLIN;

	r = poll(poll_fd1, 2, 5000);

	int x;
	int data_read;    
	if (poll_fd1[0].revents & POLLIN) 
	{
		x = 0;
        data_read = recv(sd1, recv_buffer, 65536, 0);        
    }
    if (poll_fd1[1].revents & POLLIN) 
    {
    	x = 1;
        data_read = recv(sd2, recv_buffer, 65536, 0);        
    }

//    int data_read;
    int saddr_size;
    //struct sockaddr saddr;     
    
    sd1 = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);     
    
    
    struct sockaddr_in source;
    time_t currentTime, loopTime;
    currentTime = time(NULL);
    while(1)
    {    	
		/*struct timeval tv;

		tv.tv_sec = 5;  
		tv.tv_usec = 0; 

		if ( x == 0)
			setsockopt(sd1, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));        
		else
				setsockopt(sd2, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval)); */       
    
        //data_read = recv(sd1, recv_buffer, 65536, 0);        
        loopTime = time(NULL);
        if(loopTime - currentTime >= 5)
        {
        	if(retry_value < 3)
        	{
        		fflush(stdout);
        		retry_value = retry_value + 1;
        		if ( send_receive_tcp_packets(sd, payload, destination_addr, retry_value, job, processed_job) == 0)
        		{
        			close(sd);
        			close(sd1);
        			close(sd2);
        			return 0;
        		}
        	}
        	else	
        		break;       	

        }
        if(data_read < 0)
        {
    //    	cout<<"Recv unsuccessful\n";        	    
    //    	fflush(stdout);
        	if(retry_value < 3)
        	{        		
        		fflush(stdout);
        		retry_value = retry_value + 1;
        		if ( send_receive_tcp_packets(sd, payload, destination_addr, retry_value, job, processed_job) == 0)
        		{
        			close(sd);
        			close(sd1);
        			close(sd2);
        			return 0;
        		}
        	}
        	else	
        		break;       	

        }
        else
        {
           	struct iphdr *ip_header = (struct iphdr*)recv_buffer;        
        	memset(&source, 0, sizeof(source));
        	source.sin_addr.s_addr = ip_header->saddr;
        	char str_source[INET_ADDRSTRLEN];
		    inet_ntop(AF_INET, &(source.sin_addr), str_source, INET_ADDRSTRLEN);
		
    		if (strcmp(str_source,str_destination) == 0)
    		{
    		
    			if( x == 0)//ip_header->protocol == IPPROTO_TCP)//x == 0)
    			{
    		
    				struct tcphdr *tcp_header1 = (struct tcphdr*)(recv_buffer + (int)(ip_header->ihl*4));
    		
    				if((tcp_header1->rst == 1 && tcp_header1->syn == 1) || tcp_header1->rst == 1)
    				{   				
    		
       						if(job.scans == "SYN")
    						{
  								processed_job->syn_scan = "SYN(Closed)";
    						}
							else if(job.scans == "ACK")
							{
								processed_job->ack_scan = "ACK(Unfiltered)";
	//							printf("close\n");
							}
							else if(job.scans == "NULL")
							{
								processed_job->null_scan = "NULL(Closed)";
							}
							else if(job.scans == "FIN")
							{
								processed_job->fin_scan = "FIN(Closed)";
							}
							else if(job.scans == "XMAS")
							{
								processed_job->xmas_scan = "XMAS(Closed)";
							}
    				}
    				else if((tcp_header1->syn == 1 && tcp_header1->ack == 1) || (tcp_header1->syn == 1))
    				{	
    					if(job.scans == "SYN")
								processed_job->syn_scan = "SYN(Open)";
						if(job.scans == "ACK")
						{
	//						printf("syn close\n");
								processed_job->ack_scan = "ACK(Unfiltered)";							
						}
    				}    				
    				
   		 		}
    			else if( x == 1)//ip_header->protocol == 1)//x == 1)
    			{
    //				printf("icmp pace\n");
    				struct icmphdr *icmp_header = ( struct icmphdr*) (recv_buffer + (int)(ip_header->ihl*4));
    				if(icmp_header-> type == 3)
	    			{
    					if(icmp_header->code == 1 || icmp_header->code == 2 || icmp_header->code == 3 ||
    						icmp_header->code == 9 || icmp_header->code == 10 || icmp_header->code == 13)
    					{
    						if(job.scans == "SYN")
								processed_job->syn_scan = "SYN(Filtered)";
							if(job.scans == "ACK")
								processed_job->ack_scan = "ACK(Filtered)";
							if(job.scans == "NULL")
								processed_job->null_scan = "NULL(Open|Filtered)";
							if(job.scans == "FIN")
								processed_job->fin_scan = "FIN(Open|Filtered)";
							if(job.scans == "XMAS")
								processed_job->xmas_scan = "XMAS(Open|Filtered)";		
    					}
    				}
    			}    
    			break;
    		}
        }        
    }
    close(sd);
    close(sd1);
    close(sd2);
    return 1;
}

int send_receive_udp_packets(int sd, char *payload, sockaddr_in destination_addr, int retry_value, struct jobs job, jobs * processed_job, int payload_length)
{	
	//printf("UDP FUNCTION\n");
	if(retry_value >= 3)
	{
		close(sd);
		return 0;
	}

	int sentChars;
	strcpy(payload, "globetrotter\0");
	//printf("%s\n", payload);
	//cout<<strlen(payload)<<endl;
	destination_addr.sin_port = htons(job.all_ports);
	//cout<<"prt to send at: "<<job.all_ports<<endl;
	//if ((sentChars = sendto(sd, payload, sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(payload) , 0, (struct sockaddr *)&destination_addr, sizeof(destination_addr))) < 0)	
	if(job.all_ports != 53)
	{
		if ((sentChars = sendto(sd, payload, strlen(payload) , 0, (struct sockaddr *)&destination_addr, sizeof(destination_addr))) < 0)	
    	{
    		//perror(" Error: ");
        	//cout<<"Attempt to send syn packet failed"<<endl;
        	close(sd);
        	return 1;
    	}
    	else
    	{
    		//cout<<"Attempt to send syn packet successful"<<endl;
    		//cout<<"Sent chars: "<<sentChars<<endl;
    	}
    }
    else
    {
    	//printf("calling dns\n");
    	create_dns_packet(job);
    }
    char str_destination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(destination_addr.sin_addr), str_destination, INET_ADDRSTRLEN);
	
    	
    int sd1, sd2, r, y;         
    int data_read;
    int saddr_size;
    struct timeval tv;

	tv.tv_sec = 5;  
	tv.tv_usec = 0; 
	
    //struct sockaddr saddr;     
    unsigned char *recv_buffer = (unsigned char *)malloc(65536);
    sd1 = socket(AF_INET , SOCK_RAW , IPPROTO_ICMP);     
    /*sd2 = socket(AF_INET , SOCK_RAW , IPPROTO_UDP);     
    //saddr_size = sizeof(saddr);

    struct pollfd poll_fd[2];
	poll_fd[0].fd = sd1;
	poll_fd[0].events = POLLIN;

	poll_fd[0].fd = sd2;
	poll_fd[0].events = POLLIN;

	r = poll(poll_fd, 2, 5000);

	if (poll_fd[0].revents & POLLIN) 
	{	y = 0;
    	setsockopt(sd1, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
    	data_read = recv(sd1, recv_buffer, 65536, 0);
    	cout<<"ICMP packet"<<endl;
	}
	if (poll_fd[1].revents & POLLIN) 
	{	
		y = 1;
    	setsockopt(sd2, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
    	data_read = recv(sd2, recv_buffer, 65536, 0);
    	cout<<"UDP packet"<<endl;
	}
*/
    int data_size;    
    struct sockaddr_in source;
    time_t currentTime, loopTime;
    currentTime = time(NULL);
    //printf("here\n");
    while(1)
    {

    	//-------------------
    	setsockopt(sd1, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
    	data_read = recv(sd1, recv_buffer, 65536, 0);
        //-------------------	


        loopTime = time(NULL);
        if(loopTime - currentTime >= 5)
        {
        	if(retry_value < 3)
        	{
        		fflush(stdout);
        		retry_value = retry_value + 1;
        		if ( send_receive_udp_packets(sd, payload, destination_addr, retry_value, job, processed_job, payload_length) == 0)
        		{
        			close(sd1);
    				close(sd2);
        			return 0;
        		}
        	}
        	else	
        		break;       	

        }
        if(data_read < 0)
        {
        	//cout<<"Recv unsuccessful\n";        	    
        	fflush(stdout);
        	if(retry_value < 3)
        	{
        		//printf("\nRetry Value:%d\n", retry_value );
        		//cout<<"Retrying to send the packet.\n";
        		fflush(stdout);
        		retry_value = retry_value + 1;
        		if ( send_receive_udp_packets(sd, payload, destination_addr, retry_value, job, processed_job, payload_length) == 0)
        		{
        			close(sd1);
    				close(sd2);
        			return 0;
        		}
        	}
        	else	
        		break;       	

        }
        else
        {
           	struct iphdr *ip_header = (struct iphdr*)recv_buffer;        
        	memset(&source, 0, sizeof(source));
        	source.sin_addr.s_addr = ip_header->saddr;
        	char str_source[INET_ADDRSTRLEN];
		    inet_ntop(AF_INET, &(source.sin_addr), str_source, INET_ADDRSTRLEN);
			
    		if (strcmp(str_source,str_destination) == 0)
    		{	
   				// if( y == 0)
    			  if( ip_header->protocol == 1)
    			{    	
    				
    				struct icmphdr *icmp_header = ( struct icmphdr*) (recv_buffer + + (int)(ip_header->ihl*4));
    				if(icmp_header-> type == 3)
	    			{

	    				if(icmp_header->code == 3)
	    				{
	
	    					processed_job->udp_scan = "UDP(Closed)";
	    					close(sd1);
    						close(sd2);
    
	    					return 1;
	    				}
    					else if(icmp_header->code == 1 || icmp_header->code == 2 || 
    						icmp_header->code == 9 || icmp_header->code == 10 || icmp_header->code == 13)
    					{
    				
    						processed_job->udp_scan = "UDP(Filtered)";
    						close(sd1);
    						close(sd2);
	    					return 1;    				
    					}
    				}
    			}
    			// else if (y == 1)
    			else if( ip_header->protocol == 17)
    			{    		
    				struct udphdr *udp_header1 = (struct udphdr*)(recv_buffer + (int)(ip_header->ihl*4));
    				processed_job->udp_scan = "UDP(Open)";
    				//if(job.all_ports == 53 &&) 
    				//cout<<"Result: "<<processed_job->udp_scan<<endl;
    				close(sd1);
    				close(sd2);
    				return 1;    				
   		 	
    			}    
    			break;
    		}
        }        
    }
    close(sd1);
    close(sd2);
    return 0;
}
string get_ip(char * buffer)
{		
	string ipv4;
	struct ifaddrs *all_interfaces, *temp_interface;
    struct sockaddr_in *source_address;    

    getifaddrs(&all_interfaces);
    for (temp_interface = all_interfaces; temp_interface; temp_interface = temp_interface->ifa_next) 
    {    
       	if (temp_interface->ifa_addr->sa_family==AF_INET && strcmp(temp_interface->ifa_name,"eth0")==0) 
       	{
           	source_address = (struct sockaddr_in *) temp_interface->ifa_addr;
           	buffer = inet_ntoa(source_address->sin_addr);           	
       	}
    }
    ipv4 = buffer;
    freeifaddrs(temp_interface);
    freeifaddrs(all_interfaces);   	
    return ipv4;
}



int main(int argc, char *argv[])
{	
	/*
	jobs job4;
	job4.all_ip = "129.79.247.87";
	job4.all_ports = 53;
	job4.scans = "UDP";
	create_dns_packet(job4);
	exit(0);*/
//------------------------------------------------------------

	readCommandLineArg(argc, argv);
//printAllArguments();
	if(scanFlag)
	{
		resolveScanArguments(all_ips,scans1,"");
		if(scans1.find("SYN") != std::string::npos)
		{
			all_s[num] = "SYN";
			num++;
		}
		if(scans1.find("FIN") != std::string::npos)
		{
			all_s[num] = "FIN";
			num++;
		}
		if(scans1.find("NULL") != std::string::npos)
		{
			all_s[num] = "NULL";
			num++;
		}
		if(scans1.find("ACK") != std::string::npos)
		{
			all_s[num] = "ACK";
			num++;
		}
		if(scans1.find("XMAS") != std::string::npos)
		{
			all_s[num] = "XMAS";
			num++;
		}
		if(scans1.find("UDP") != std::string::npos)
		{
			all_s[num] = "UDP";
			num++;
		}

	}
	else
	{
		all_s[0] = "SYN";
		all_s[1] = "ACK";
		all_s[2] = "NULL";
		all_s[3] = "FIN";
		all_s[4] = "XMAS";
		all_s[5] = "UDP";
		resolveScanArguments(all_ips,"",scans2);
		//cout<<"\nall scans after checking all scans = "<<all_scans.size();
	}

	string source_ip1;
	source_ip1 = get_ip(source_ip);	
	int i ;
	for(i=0; i< source_ip1.length(); i++)
	{
		source_ip[i] = source_ip1[i];
	}	

	//cout<<"The value of scan is : "<<speed_up<<endl;	
	

	int z;
	jobs temp1;
	time_t currentTime, loopTime;
	currentTime = time(NULL);
	//for(z = 0; z < all_scans.size() - 1; z++)
	if(speed_up == 0)
	{
		while(!all_scans.empty())
		{
			temp1 = all_scans.front();

			tcp_udp_scan(temp1);
			/*cout<<temp1.all_ip<<endl;
			cout<<temp1.all_ports<<endl;
			cout<<temp1.scans<<endl; */
			all_scans.pop();
		}
	}
	else
	{
		long id;
		pthread_t my_thread[speed_up];
		for(id = 1; id <= speed_up; id++) 
		{

        	int ret =  pthread_create(&my_thread[id], NULL, &worker_thread,(void*)id);
	        if(ret != 0) 
	        {
	            printf("Error: pthread_create() failed\n");
	            exit(EXIT_FAILURE);
	        }
	        else
	        {
	        	//printf("THread %d created\n", id);
	        }
        }

        for(id = 1; id <= speed_up; id++) 
		{
			pthread_join(my_thread[id], NULL);
		}
	}



//------------------------------------------------------------

	int temp; 
	for(temp = 0; temp < 6; temp++)
	{
		if(all_s[temp] != "")
			all_s_size++;
	}
	struct jobs job;
    

	loopTime = time(NULL);
	double secs; 
	secs = difftime(loopTime, currentTime);
	printf("Scanning took: %f seconds\n", secs );
	output();
	return 0;	
} 	

void* worker_thread(void* arg)
{
	while(!all_scans.empty())
	{
		//cout<<"Thread in use: "<<(long) arg<<endl;
		pthread_mutex_lock(&mutex_main);		
		struct jobs job_temp;
		job_temp = all_scans.front();
		all_scans.pop();
		pthread_mutex_unlock(&mutex_main);		
		usleep(1);
		tcp_udp_scan(job_temp);
	}
	pthread_mutex_destroy(&mutex_main);
	pthread_mutex_destroy(&mutex_service_name_tcp);
	pthread_mutex_destroy(&mutex_service_name_udp);
	pthread_mutex_destroy(&mutex_processed_job);
	pthread_exit(NULL);
}

void output()
{	
	draw_conclusions();
	string ip_address = ""; 
	int k = 0;
	for(k =0; k <processed_job_array_final.size(); k++)
	{		
		jobs temp_job;
		temp_job = processed_job_array_final[k];
		
		if ( ip_address == "" || ip_address != temp_job.all_ip)
		{
			ip_address = temp_job.all_ip;			
			cout<<"\nIp address: "<< ip_address<<endl;
			printf("Open Ports:\n");
			print_headers();
			print_results(ip_address, 0);
			printf("\n\nClosed/Filtered/UnFilitered Ports:\n");
			print_headers();
			print_results(ip_address, 1);
		}
		
	}
}

	void print_headers()
{
	printf("\n\n");	


	cout<<setw(5)<<"Ports"<<setw(5)<<""<<setw(30)<<"Service Name (if applicable)"<<setw(5)<<"";			
	cout<<setw(all_s_size*15)<<"";
	cout<<"Results"<<setw(10 * (6 - all_s_size))<<"";
	cout<<setw(5)<<""<<"Conclusion"<<endl;




	cout<<setfill('-')<<setw(5)<<"----"<<""<<setfill('-')<<setw(30)<<"----------------------------"<<setw(5)<<"";			
	cout<<setfill('-')<<setw(all_s_size*15)<<"";
	cout<<"-------"<<setfill('-')<<setw(10 * (6 - all_s_size))<<"";
	cout<<setfill('-')<<setw(5)<<""<<"----------"<<endl;
	
	
	//print_results("127.23.45.73", 0);		

//	print_results("127.23.45.73", 1);
}
void print_results(string ip_address, int status)
{

	cout<<setfill(' ');
	int i;
	int j;

	for(i = 0; i < processed_job_array_final.size(); i++)
	{
		//cout<<" Status: "<<status<<endl;
		//cout<<"Conclusion: "<<processed_job_array_final[i].conclusion<<endl;
		if(processed_job_array_final[i].all_ip == ip_address)
		{

			if  ((status == 0 && processed_job_array_final[i].conclusion == "Open") || (status == 1 && processed_job_array_final[i].conclusion != "Open"))
			{
				printf("\n");
				cout<<setw(5)<<processed_job_array_final[i].all_ports<<setw(5)<<""<<setw(30)<<processed_job_array_final[i].service_name<<setw(5)<<"";			
			
				int j;
				for(j = 0; j < all_s_size; j++)		
				{
					if(all_s[j] == "SYN")
						cout<<setw(10)<<processed_job_array_final[i].syn_scan<<setw(5)<<"";
					else if(all_s[j] == "NULL")
						cout<<setw(10)<<processed_job_array_final[i].null_scan<<setw(5)<<"";				
					else if(all_s[j] == "ACK")
						cout<<setw(10)<<processed_job_array_final[i].ack_scan<<setw(5)<<"";
					else if(all_s[j] == "FIN")
						cout<<setw(10)<<processed_job_array_final[i].fin_scan<<setw(5)<<"";
					else if(all_s[j] == "XMAS")
						cout<<setw(10)<<processed_job_array_final[i].xmas_scan<<setw(5)<<"";
					else if(all_s[j] == "UDP")
						cout<<setw(10)<<processed_job_array_final[i].udp_scan<<setw(5)<<"";			

				}	
				if(all_s_size == 6)
				{
					cout<<setw( 10 +  (10 * (5 - all_s_size)))<<"";
					cout<<setw( 5 + (5 * ( 5 - all_s_size)))<<""<<processed_job_array_final[i].conclusion<<endl;
				}
				else
				{
					cout<<setw((10 * (5 - all_s_size)))<<"";
					cout<<setw((5 * ( 5 - all_s_size)))<<""<<processed_job_array_final[i].conclusion<<endl;
				}

			}
		}
	}


}
void consolidate_jobs()
{	
	//cout<<all_processed_jobs.size()<<endl;
	vector<jobs> processed_job_array;
	//exit(0);
	int k;	
	for(k= all_processed_jobs.size()-1; k >= 0 ; k--)
	{

		processed_job_array.push_back(all_processed_jobs[all_processed_jobs.size()-1 - k]);
		//all_processed_jobs.pop_back();
	}
	//printf("in consolidate_jobs: \n");
	//cout<<processed_job_array[0].syn_scan<<endl;
	//cout<<"just Size: "<<processed_job_array.size()<<endl;
	k = 0;
	int j = 0;
	jobs temp_job;
	for(k = 0; k < processed_job_array.size(); k++)
	{	
		if(processed_job_array[k].all_ip != "")
		{
			temp_job.all_ip = processed_job_array[k].all_ip;
			temp_job.all_ports= processed_job_array[k].all_ports;
			temp_job.service_name = processed_job_array[k].service_name;
			int l = 0;
			jobs temp;
			//cout<<"Processing Out Ip:"<<temp_job.all_ip<<endl;
			//cout<<"Processing Out port:"<<temp_job.all_ports<endl;
			for(l=k; l < processed_job_array.size(); l++)
			{
				if(processed_job_array[l].all_ip != "")
				{
					temp = processed_job_array[l];
					//cout<<"Processing Ip:"<<temp.all_ip<<endl;
					//cout<<"Processing port:"<<temp.all_port<<endl;					
					if(temp_job.all_ip == temp.all_ip && temp_job.all_ports== temp.all_ports)
					{
						//printf("You are here\n");
						if(temp.syn_scan != "")
						{
							///cout<<"Syn: "<<temp.syn_scan<<endl;
							temp_job.syn_scan = temp.syn_scan;
						}
						else if(temp.null_scan != "")
						{
							//cout<<"Null: "<<temp.null_scan<<endl;
							temp_job.null_scan = temp.null_scan;
						}
						else if(temp.xmas_scan != "")
						{
							//cout<<"Xmas: "<<temp.xmas_scan<<endl;
							temp_job.xmas_scan = temp.xmas_scan;
						}
						else if(temp.fin_scan != "")
						{
							//cout<<"Fin: "<<temp.fin_scan<<endl;
							temp_job.fin_scan = temp.fin_scan;
						}
						else if(temp.ack_scan != "")
						{
							//cout<<"Ack: "<<temp.ack_scan<<endl;
							temp_job.ack_scan = temp.ack_scan;
						}
						else if(temp.udp_scan != "")
						{
							//cout<<"Udp: "<<temp.udp_scan<<endl;
							temp_job.udp_scan = temp.udp_scan;
						}
						processed_job_array[l].all_ip = "";
					}
				}
	
			}
			all_processed_jobs_final.push_back(temp_job);			
			j++;
		}	
	}
}
void draw_conclusions()
{
	consolidate_jobs();
	jobs temp_temp;
	


	int k = 0;
	jobs temp_job;
	//cout<<"Size is draw_conclusions: "<<all_processed_jobs_final.size()<<endl;
	//while(!all_processed_jobs_final.empty())
	for(k = 0; k < all_processed_jobs_final.size(); k++)
	{
	

		temp_job = all_processed_jobs_final[k];		
		//all_processed_jobs_final.pop_back();
		


		if(temp_job.syn_scan=="SYN(Open)" || (temp_job.udp_scan=="UDP(Open)" && temp_job.ack_scan != "ACK(Unfiltered)") ||
		 (temp_job.null_scan=="NULL(Open)" && temp_job.ack_scan != "ACK(Unfiltered)") ||
		 (temp_job.xmas_scan=="XMAS(Open)" && temp_job.ack_scan != "ACK(Unfiltered)") ||
		 (temp_job.fin_scan=="FIN(Open)" && temp_job.ack_scan != "ACK(Unfiltered)"))
		{

			temp_job.conclusion = "Open";
		}
		else if(temp_job.syn_scan=="SYN(Closed)" || temp_job.null_scan=="NULL(Closed)"|| temp_job.xmas_scan=="XMAS(Closed)"
			||temp_job.fin_scan=="FIN(Closed)" || temp_job.udp_scan=="UDP(Closed)" )
		{
			temp_job.conclusion = "Closed";
		}
		else if (temp_job.ack_scan == "ACK(Filtered)" || temp_job.syn_scan == "SYN(Filtered)" || temp_job.null_scan == "NULL(Filtered)" ||
			temp_job.xmas_scan == "XMAS(Filtered)" || temp_job.fin_scan == "FIN(Filtered)" || temp_job.udp_scan == "UDP(Filtered)")
		{
			temp_job.conclusion = "Filtered";
		}
		else if(temp_job.ack_scan == "ACK(Unfiltered)")
		{
			temp_job.conclusion = "Unfiltered";
		}
		else if(temp_job.null_scan=="NULL(Open|Filtered)"|| temp_job.xmas_scan=="XMAS(Open|Filtered)"
			||temp_job.fin_scan=="FIN(Open|Filtered)" ||temp_job.udp_scan=="UDP(Open|Filtered)")
			{
			temp_job.conclusion = "Open|Filtered";	
		}
		//printf("here after conclusion:%d\n", k);
		//cout<<"Conclusion: "<<temp_job.conclusion<<endl;
		processed_job_array_final.push_back(temp_job);
	/*	cout<<"Ip: "<<temp_job.all_ip<<endl;
		cout<<"Port: "<<temp_job.all_ports<endl;
		cout<<"Syn: "<<temp_job.syn_scan<<endl;
		cout<<"Ack: "<<temp_job.ack_scan<<endl;
		cout<<"Null: "<<temp_job.null_scan<<endl;
		cout<<"Xmas: "<<temp_job.xmas_scan<<endl;
		cout<<"Conclusion: "<<temp_job.fin_scan<<endl;
		cout<<"Conclusion: "<<temp_job.conclusion<<endl;
	*/	
	}	
	//	cout<<"Conclusion: "<<processed_job_array_final.size()<<endl;
}

void create_dns_packet(jobs job)
{

	//cout<<"in create dns packet"<<endl;
	struct sockaddr_in destination_addr;
	destination_addr.sin_family = AF_INET;
    
    //destination address
    char temp_addr[16];
    int j;    
	for(j=0; j < job.all_ip.length(); j++)
	{
		temp_addr[j] = job.all_ip[j];
	}
	temp_addr[job.all_ip.length()] = '\0';	
	destination_addr.sin_port = htons(53);
	inet_pton(AF_INET, temp_addr, &destination_addr.sin_addr);	


	int s;
	unsigned char payload[65536], *name;
	struct dns_question *query;
	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP);
	dns_header *dns;
	dns = (struct dns_header *)&payload;
	dns->id = (unsigned short) htons(rand() % 65535);
	

    dns->qr = 0; 
    dns->opcode = 0;
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = 1;
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    name =(unsigned char*)&payload[sizeof(struct dns_header)];
    char name1[17] = "3www6google3com0";
    //name =(unsigned char *) &name1;
    int q;
    for(q = 0; q < strlen(name1);q++)
    {
    	name[q] = name1[q];    	
    }
    name[strlen(name1)] = '\0';
    query =(struct dns_question *)&payload[sizeof(struct dns_header) + (strlen((const char*)name1)+1)]; //fill it
 
    query->qtype = htons(1); //type of the query , A , MX , CNAME , NS etc
    query->qclass = htons(1); //its internet (lol)
 
    //printf("\nSending Packet..."); 	
    if( sendto(s,(char*)payload,sizeof(struct dns_header) + (strlen((const char*)name1)+1) + sizeof(struct dns_question),0,(struct sockaddr*)&destination_addr,sizeof(destination_addr)) < 0)
    {
        //perror("sendin failed..");

    }
    else	
    {
    	//printf("Sent successfully\n");
    }

     /*printf("\nReceiving answer...");
    if(recv(s,(char*)payload , 65536 , 0 ) < 0)
    {
        //perror("recvfrom failed");
    }
    //printf("Done");
 
    dns = (struct dns_header*) payload;

    if(dns->qr == 1)
    	printf("Response received\n");*/
}
//-------------------------------------
//--------------------------------------

void resolveScanArguments(queue<jobs> all_ips,string a1,string a2)
{
	if(!a1.empty())
	{
	//User specified Scans
	while(!all_ips.empty())
	{
		temp_job = all_ips.front();
		all_ips.pop();
		if(a1.find("SYN") != std::string::npos)
		{
			populateMultiThreadQueue(all_ips,"SYN");
		}
		if(a1.find("FIN") != std::string::npos)
		{
		populateMultiThreadQueue(all_ips,"FIN");
		}
		if(a1.find("NULL") != std::string::npos)
		{
			populateMultiThreadQueue(all_ips,"NULL");
		}
		if(a1.find("ACK") != std::string::npos)
		{
			populateMultiThreadQueue(all_ips,"ACK");
		}
		if(a1.find("XMAS") != std::string::npos)
		{
			populateMultiThreadQueue(all_ips,"XMAS");
		}
		if(a1.find("UDP") != std::string::npos)
		{
			populateMultiThreadQueue(all_ips,"UDP");
		}
	}

	}
	if(!a2.empty())
	{
		//No scan specified- default: all scans
		while(!all_ips.empty())
		{
			temp_job = all_ips.front();
			all_ips.pop();
			if(a2.find("SYN") != std::string::npos)
			{
				populateMultiThreadQueue(all_ips,"SYN");
			}
			if(a2.find("FIN") != std::string::npos)
			{
				populateMultiThreadQueue(all_ips,"FIN");
			}
			if(a2.find("NULL") != std::string::npos)
			{
				populateMultiThreadQueue(all_ips,"NULL");
			}
			if(a2.find("ACK") != std::string::npos)
			{
				populateMultiThreadQueue(all_ips,"ACK");
			}
			if(a2.find("XMAS") != std::string::npos)
			{
				populateMultiThreadQueue(all_ips,"XMAS");
			}
			if(a2.find("UDP") != std::string::npos)
			{
				populateMultiThreadQueue(all_ips,"UDP");
			}
		}
	}
}

void populateMultiThreadQueue(queue<jobs> all_ips, string scanType)
{
	temp_job_new.all_ip = temp_job.all_ip;
	temp_job_new.all_ports = temp_job.all_ports;
	temp_job_new.scans = scanType;
	all_scans.push(temp_job_new);
}
void readCommandLineArg(int argc, char* argv[])
{
	int ch = 0;
	static struct option longopts[] = {
		{"help", no_argument, NULL,'h'},
		{"port", required_argument, NULL, 'l'},
		{"ip", required_argument, NULL, 'i'},
		{"file", required_argument, NULL, 'f'},
		{"prefix", required_argument, NULL, 'x'},
		{"scan", required_argument, NULL, 's'},
		{"speedup", required_argument, NULL, 'u'},
		{0,0,0,0}
	};
	while((ch = getopt_long(argc, argv,"h:l:i:f:x:s:u:",longopts,NULL)) != -1 )
	{
		if(ch == -1)
		break;
		switch(ch) {
		case 'h':
			printHelpScreen();
			break;
		case 'l':
			resolvePortArguments(optarg);
			break;
		case 'i':
			resolveIpArguments(optarg);
			break;
		case 'f':
			resolveFileArguments(optarg);
			break;
		case 'x':
			resolvePrefixArguments(optarg);
			break;
		case 's':
			{
			scanFlag = 1;
			scans1 = (string) optarg;
			break;
			}
		case 'u':
		{
				speed_up = atoi(optarg);
				if(speed_up > 100)
					speed_up = 100;
				//cout<<"\nspeedup is = "<<speedup;
				break;
		}
		default:
			cout<<"Incorrect information as command line argument"<<endl;
		break;
	}
	}
}


void printHelpScreen()
{
	cout<<"\n";
	cout<<"\t\t\t--help <prints help screen>"<<endl;
	cout<<"\t\t\t--port <scans specefic port>"<<endl;
	cout<<"\t\t\t--ip <scans the specefic port of the specified ip>"<<endl;
	cout<<"\t\t\t--prefix <scans a range of ip depending on the prefix number>"<<endl;
	cout<<"\t\t\t--file <scans the specefic ports on all the prefixed ips and regular ips provided>"<<endl;
	cout<<"\t\t\t--speedup <provides the number of threads that should be executed>"<<endl;
	cout<<"\t\t\t--scan <gives the list of scans that should be performed>"<<endl;
	exit(0);
}

void resolvePortArguments(char* optarg1)
	{
	if(strchr(optarg1,',')!=NULL)
	{
		const char range1[2] = ",";
		char* token1;
		token1 = strtok(optarg1,range1);
		int port_num1 = 0;
		char* ports1[port_num1];
		while(token1!=NULL)
		{
			ports1[port_num1] = (char*)malloc (strlen(token1)+1);
			strcpy(ports1[port_num1],token1);
			token1 = strtok(NULL,range1);
			port_num1++;
		}
		p_num_cs = port_num1;
		
		for(p1 = 0; p1 < p_num_cs; p1++)
		{
			if(strchr(ports1[p1],'-')!=NULL)
				resolvecsPortArguments(ports1[p1]);
			else
			{
				a.range_cs_ports[range_cs_ports_counter] = atoi(ports1[p1]);
				range_cs_ports_counter++;
			}
		}
		csPortsFlag = 1;
	}
	else if(strchr(optarg1,'-')!=NULL)
	{
		if(strchr(optarg1,',')==NULL)
			resolvecsPortArguments(optarg1);
	}
	else
	{
		a.port = atoi(optarg1);
		singlePortFlag = 1;
	}
}

void resolvecsPortArguments(char* optarg1)
{
const char range2[2] = "-";
char* token2;
token2 = strtok(optarg1,range2);
int port_num2 = 0;
char* ports2[2];
while(token2!=NULL)
{
ports2[port_num2] = (char*)malloc (strlen(token2)+1);
strcpy(ports2[port_num2],token2);
token2 = strtok(NULL,range2);
port_num2++;
}
for(port_num2 = atoi(ports2[0]); port_num2 <= atoi(ports2[1]); port_num2++)
{
a.range_ports[p_num_range] = port_num2;
p_num_range++;
}

for(port_num2 = 0; port_num2 < 2; port_num2++)
{
free(ports2[port_num2]);
}
rangePortsFlag = 1;
}

void resolveIpArguments(char* optarg2)
{
if(singlePortFlag)
scanPorts(a.port,optarg2);

if(csPortsFlag)
{
for(p1 = 0; p1 < range_cs_ports_counter; p1++)
{
scanPorts(a.range_cs_ports[p1],optarg2);
}
}

if(rangePortsFlag)
{
for(p1 = 0; p1 < p_num_range ; p1++)
{
scanPorts(a.range_ports[p1],optarg2);
}
}
}

void resolveFileArguments(char* optarg)
{
string line;
ifstream myfile(optarg);
if(myfile.is_open())
{
while(getline(myfile,line))
{
if(line.length() > 6)
{
a.x = line.c_str();
a.y = (char*) malloc(sizeof(char) * (strlen(a.x) + 1));
strcpy(a.y,a.x);
if(strchr(a.y,'/')!=NULL)
resolvePrefixArguments(a.y);
else
resolveIpArguments(a.y);
}
}
myfile.close();
}
else
cout<<"Invalid File given as input";
}

void resolvePrefixArguments(char* optarg)
{
const char slashSeperator[2] = "/";
char* tokenPrefix;
tokenPrefix = strtok(optarg,slashSeperator);
int prefixValue = 0;
char* seperatedValues[2];
while(tokenPrefix!=NULL)
{
seperatedValues[prefixValue] = (char*)malloc (strlen(tokenPrefix)+1);
strcpy(seperatedValues[prefixValue],tokenPrefix);
tokenPrefix = strtok(NULL,slashSeperator);
prefixValue++;
}
a.ip_addresses = seperatedValues[0];
a.prefix = atoi(seperatedValues[1]);
calculatePrefix(a.prefix,a.ip_addresses);
}

void calculatePrefix(int prefixVal,char* ipVal)
{

if(prefixVal <= 32)
{
if(prefixVal == 32)
{
resolveIpArguments(ipVal);
}
else
{
const char dotSeperator[2] = ".";
char* tokenIpParts;
tokenIpParts = strtok(ipVal,dotSeperator);
int ipParts = 0;
int ipAddr[4];
char* seperatedIpValues[4];
while(tokenIpParts!=NULL)
{
seperatedIpValues[ipParts] = (char*)malloc (strlen(tokenIpParts)+1);
strcpy(seperatedIpValues[ipParts],tokenIpParts);
tokenIpParts = strtok(NULL,dotSeperator);
ipParts++;
}
if(ipParts == 4)
{
int n = 0;
int validIp = 0;
for(n = 0; n < ipParts; n++)
{
if(atoi(seperatedIpValues[n]) >= 0 && atoi(seperatedIpValues[n])<256)
{
ipAddr[n] = atoi(seperatedIpValues[n]);
validIp = 1;
}
else
cout<<"\nInvalid Ip Address entered";
}
if(validIp)
{
int currentIp[4];
int *resultantIp;
int arraySize = pow(2,(32-prefixVal));
resultantIp = (int*) malloc(arraySize * sizeof(ipAddr));
int n = 0;
for(n = 0; n < 4 ; n++)
{
currentIp[n] = ipAddr[n];
}
int riCounter = 0;
int loopCounter4  = 0;
int loopCounter3  = 0;
int loopCounter2  = 0;
int loopCounter1  = 0;
int tempAddr4;
int tempAddr3;
int tempAddr2;
int tempAddr1;
if(prefixVal>=24)
loopCounter4 = pow(2,(32-prefixVal));
else
loopCounter4 = 256;

tempAddr4 = ipAddr[3] & (255 - loopCounter4 + 1);
int i = 0;
for(i=0; i<loopCounter4; i++)
{
currentIp[3] = tempAddr4 | i;
resultantIp[riCounter] = currentIp[3];
if(prefixVal>=24)
assignIpAddress(currentIp,resultantIp);
riCounter++;
if(prefixVal<24)
{
if(prefixVal>=16)
loopCounter3 = pow(2,(24-prefixVal));
else
loopCounter3 = 256;
tempAddr3 = ipAddr[2] & (255 - loopCounter3 + 1);
int j = 0;
for(j=0; j<loopCounter3; j++)
{
currentIp[2] = tempAddr3 | j;
resultantIp[riCounter] = currentIp[2];
if(prefixVal>=16)
assignIpAddress(currentIp,resultantIp);
riCounter++;
if(prefixVal<16)
{
if(prefixVal>=8)
loopCounter2 = pow(2,(16-prefixVal));
else
loopCounter2 = 256;
tempAddr2 = ipAddr[1] & (255 - loopCounter2 + 1);
int k = 0;
for(k=0; k<loopCounter2; k++)
{
currentIp[1] = tempAddr2 | k;
resultantIp[riCounter] = currentIp[1];
if(prefixVal>=8)
assignIpAddress(currentIp,resultantIp);
riCounter++;
if(prefixVal<8)
{
if(prefixVal>=0)
loopCounter1 = pow(2,(8-prefixVal));
else
loopCounter1 = 256;
tempAddr1 = ipAddr[0] & (255 - loopCounter1 + 1);
int l = 0;
for(l=0; l<loopCounter1; l++)
{
currentIp[0] = tempAddr1 | l;
resultantIp[riCounter] = currentIp[0];
if(prefixVal>=0)
assignIpAddress(currentIp,resultantIp);
riCounter++;
}
}
}
}
}
}
}
}
}
else
cout<<"\nInvalid Ip Address entered";
}
}
else
cout<<"\nInvalid prefix, please re-enter";
}

void assignIpAddress(int currentIp[4], int* resultantIp)
{
	int i = 0;

	char prefixedIp[16];
	char* prefixedIps;
	sprintf(prefixedIp,"%d.%d.%d.%d",currentIp[0],currentIp[1],currentIp[2],currentIp[3]);
	//cout<<"\nprefixedIp = "<<prefixedIp;
	prefixedIps = prefixedIp;
	//cout<<"\nprefixedIps = "<<prefixedIps;

	resolveIpArguments(prefixedIps);
}

void scanPorts(int port,char* ip_addresses)
{
	j.all_ip = ip_addresses;
	j.all_ports = port;
	all_ips.push(j);
}

void printAllArguments()
{
	cout<<"\nmy queue contains = ";
	cout<<"\nqueue size = "<<all_ips.size();
}

