#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "send.h"

#define MYPORT 5000
#define MAXBUFLEN 200    /* the port users will be connecting to */

int sockfd;
struct sockaddr_in their_addr; /* connector's address information */

void initSend(char *host) {
  if(host) {
    tiudp tipacket;
    struct hostent *he;
    char buf[MAXBUFLEN];            /*The buffer that we read / write each time     */
    int addr_len;/* Address length for the network functions
		    that require that      */


    if ((he=gethostbyname(host)) == NULL) {  /* get the host info */
      herror("gethostbyname");
      exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
      perror("socket err");
      exit(1);
    }

    their_addr.sin_family = AF_INET;      /* host byte order */
    their_addr.sin_port = htons(MYPORT);  /* short, network byte order */
    their_addr.sin_addr = *((struct in_addr *)he->h_addr);
    bzero(&(their_addr.sin_zero), 8);     /* zero the rest of the struct */
  }
}

uint32_t packetNumber;

void sendUDP(tiudp *data) {
  if(sockfd) {
    int numbytes;
    data->packetInfo=3;
    data->packetNumber=packetNumber++;
    data->payloadLength=data->packetLen + 1;
    if ((numbytes=sendto(sockfd, (char*)data, sizeof(tiudp) + data->packetLen, 0,		\
			 (struct sockaddr *)&their_addr, sizeof(struct sockaddr))) == -1) {
      perror("sendto err");
      exit(1);
    }
    //printf("sent %d bytes to %s\n",numbytes,inet_ntoa(their_addr.sin_addr));
  }
} 
