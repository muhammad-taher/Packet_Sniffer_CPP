#include<bits/stdc++.h>
#include<pcap.h>
#include<ctime>
#include<cstdio>
#include<netinet/in.h>
#include<arpa/inet.h>
using namespace std;

#define ADDR_LEN 6
#define ETHERNET_LEN 14


struct  ethernet_header{
    u_char dAddr[ADDR_LEN];
    u_char sAddr[ADDR_LEN];
    u_short ether_type;
};

struct ip_header{
    u_char ip_version_HeaderLenght;
    u_char ip_typesOfService;
    u_short ip_totalLenght;
    u_short ip_identification;
    u_short ip_fragOff;
    u_char ip_timeToLive;
    u_char ip_protocol;
    u_short ip_checkSum;
    struct in_addr ip_src, ip_dst;
};

struct tcp_header {
    u_short th_sport;   
    u_short th_dport;   
    u_int   th_seq;
    u_int   th_ack;
    u_char  th_offx2;
    u_char  th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};



void packet_handler(u_char *param, const struct pcap_pkthdr *header , const u_char *pkt_data){
    time_t local_tm=header->ts.tv_sec;
    struct tm *ltime;
    char timestr[16];

    ltime=localtime(&local_tm);
    strftime(timestr,sizeof(timestr),"%H:%M:%S",ltime);

    cout<<"Packet Captured at : "<<"["<<timestr<<"]"<<" Length : "<<header->len<<" bytes"<<endl;
    
    const struct ethernet_header *ethernet;
    const struct ip_header *ip;
    const struct tcp_header *tcp;


    ethernet=(struct ethernet_header*)(pkt_data);

    cout<<"Source Address : "<<endl;
    for(int i=0;i<6;i++){
        printf("%02x",ethernet->sAddr[i]);
        if(i<5){cout<<":";}

    }
    cout<<endl;
    cout<<"Destination Address : "<<endl;
    for(int i=0;i<6;i++){
        printf("%02x",ethernet->dAddr[i]);
        if(i<5){cout<<":";}
    }

    cout<<endl;

    if(ntohs(ethernet->ether_type)==0x0800){
        cout<<"Type : IPv4"<<endl;
        ip=(struct ip_header*)(pkt_data+ETHERNET_LEN);
        cout<<"Source ip Address  : "<<inet_ntoa(ip->ip_src)<<endl;
        cout<<"Destination ip Address  : "<<inet_ntoa(ip->ip_dst)<<endl;
        int ptcl=(int)ip->ip_protocol;
        cout<<"Protocol : "<<ptcl<<endl;

        if(ptcl==6){
            cout<<"Protocol : TCP"<<endl;
            int ipHeaderLen=(ip->ip_version_HeaderLenght & 0x0f)*4;
            tcp=(struct tcp_header*)(pkt_data+14+ipHeaderLen);
            cout<<"Source Port : "<<ntohs(tcp->th_sport)<<endl;
            cout<<"Destination Port : "<<ntohs(tcp->th_dport)<<endl;
        }
    }
    else if(ntohs(ethernet->ether_type)==0x806){
        cout<<"Type : ARP"<<endl;
    }
    else{
        cout<<"Type : Unknown"<<endl;
    }


}
int main(){
    char errBuff[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    if(pcap_findalldevs(&alldevs,errBuff)==-1){
        cout<<"Error Finding Device : "<<errBuff<<endl;
        return 0;
    }
    for(d=alldevs;d!=NULL;d=d->next){
        cout<<++i<<" : "<<d->name<<endl;
        if(d->description){
            cout<<"Description : "<<d->description<<endl;
        }
        else{
            cout<<"No Description Available"<<endl;
        }
        
    }
    if(i==0){
        cout<<"No device Found"<<endl;
    }

    pcap_t *packet;
    int num;
    cout<<"Enter The Adapter number"<<endl;
    cin>>num;
    if(num>i || num<0){
        cout<<"Enter a valid Number that must be in range "<<0<< " to "<<i<<endl;
    }
    d=alldevs;
    for(int k=1;k<num;k++){
        d=d->next;
    }
    if(d==NULL){
        cout<<"Found d is NULL"<<endl;
    }
    else{
        cout<<"Sniffing Packet for adapter : "<<d->name<<endl;
    }
    packet=pcap_open_live(d->name,65536,1,1000,errBuff);
    if(packet==NULL){
        cout<<"Getting NULL in Packet pointer "<<endl;
    }
    else{
        cout<<"Getting Packet Successfully"<<endl;
    }
    
    pcap_freealldevs(alldevs);
    pcap_loop(packet,0,packet_handler,NULL);
    return 0;
    
}