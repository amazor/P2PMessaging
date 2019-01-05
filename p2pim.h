#ifndef P2PIM_H
#define P2PIM_H
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define BUFFER_SIZE 255
#define DEFAULT_UDP_PORT 50558
#define DEFAULT_TCP_PORT 50559
#define DEFAULT_INIT_TIMEOUT 5
#define DEFAULT_MAX_TIMEOUT 60
#define MAX_NUMBER_OF_USERS 15

struct Peer* createPeer(struct Packet* pkt, sockaddr_in* fromAddress);
void addPeer(struct Peer* peer);
void createTCPConnection(struct Peer* peer);
int addToPolledFD(int filedescriptor);
int buildPacket(struct Packet* packet, uint16_t opCode, uint16_t udp, uint16_t tcp, char *hostname, char *username, char *message);
void error(const char *message);
void SignalHandler(int param);
int makeUDPSocket(struct sockaddr_in *ServerAddress, uint16_t UDPport);
int makeTCPSocket(struct sockaddr_in *ServerAddress, uint16_t TCPport);
int parseHostnameUsername(char* origString, char* hostname, char* username);
void makeTCPConnection (int TCPport, char * hostname );



#endif // P2PIM_H
