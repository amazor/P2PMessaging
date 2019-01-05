/*
 * p2pMessenger.cpp
 *
 *  Created on: Jan 5, 2019
 *      Author: amazor
 */
#include <ncurses.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <panel.h>

#include "p2pim.h"
#include "packetTypes.h"
#include "peerInfo.h"

void init_UI();
WINDOW *create_newwin(int height, int width, int starty, int startx);
void destroy_win(WINDOW *local_win);

void remove_peer_from_window();
void add_peer_to_window(struct Peer * peer);

WINDOW * peersWindow;
WINDOW * DEFAULT_CHAT_WINDOW;
WINDOW * typeWindow;
PANEL * DEFAULT_CHAT_PANEL;

int udpSocketFD, tcpSocketFD;
struct sockaddr_in *broadcastAddress = (struct sockaddr_in*) malloc(
		sizeof(struct sockaddr));
char username[255], hostname[255];

uint16_t UDPport = DEFAULT_UDP_PORT;
uint16_t TCPport = DEFAULT_TCP_PORT;
int minTimeout = DEFAULT_INIT_TIMEOUT;
int maxTimeout = DEFAULT_MAX_TIMEOUT;

// list of peers
std::vector<struct Peer*> peers;

// list of all File Descriptors to be polled
std::vector<struct pollfd> polledFDs;

int main(int argc, char *argv[]) {
	init_UI();

	std::vector<char> stdInBuff;

	//current peer being referenced. -1 means there is no peer being referenced.
	int currentPeerIndex = -1;

	DEFAULT_CHAT_PANEL = new_panel(DEFAULT_CHAT_WINDOW);

	int Result; // Used for results of functions to check for errors

	struct sockaddr_in *ServerAddressUDP, *ServerAddressTCP, *fromAddress;
	socklen_t fromAddressLength = sizeof(fromAddress); // length of fromAddress

	// Allocate memory for UDP and TCP addresses
	// Also allocates memory for fromAddress which will be used when receiving packets
	ServerAddressUDP = (struct sockaddr_in*) malloc(sizeof(struct sockaddr));
	ServerAddressTCP = (struct sockaddr_in*) malloc(sizeof(struct sockaddr));
	fromAddress = (struct sockaddr_in*) malloc(sizeof(struct sockaddr));

	//make sockets for UDP and TCP servers
	udpSocketFD = makeUDPSocket(ServerAddressUDP, UDPport);
	tcpSocketFD = makeTCPSocket(ServerAddressTCP, TCPport);

	//broadcast address uses UDP port -- just change ip address
	memcpy(broadcastAddress, ServerAddressUDP, sizeof(struct sockaddr));
	broadcastAddress->sin_addr.s_addr = inet_addr("255.255.255.255");

	//packet pointers used for sending and receiving
	struct Packet *sendPacket = (struct Packet*) malloc(sizeof(struct Packet));
	struct Packet *receivePacket = (struct Packet*) malloc(
			sizeof(struct Packet));

	//zero out packets
	bzero(sendPacket, sizeof(struct Packet));
	bzero(receivePacket, sizeof(struct Packet));

	int sizeOfPacket = 0;
	int currentTimeout = minTimeout;
	int ch;

	// get username and hostname
	gethostname(hostname, 255);
	strcpy(username, getenv("USER"));
	strcpy(hostname, gethostbyname(hostname)->h_name);

	//set up signals to direct to SignalHandler function
	//used to exit program and send a closing packet to peers
	signal(SIGTERM, SignalHandler);
	signal(SIGINT, SignalHandler);
	signal(SIGUSR1, SignalHandler);

	addToPolledFD(STDIN_FILENO);
	addToPolledFD(udpSocketFD);
	addToPolledFD(tcpSocketFD);

	//build a discovery UDP packet
	sizeOfPacket = buildPacket(sendPacket, PACKET_DISCOVERY, UDPport, TCPport,
			hostname, username, NULL);

	// Send discover UDP packet from UDP server broadcasted
	Result = sendto(udpSocketFD, sendPacket, sizeOfPacket, 0,
			(struct sockaddr *) broadcastAddress, sizeof(struct sockaddr));

	if (0 > Result) {
		error("ERROR sending to server");
	}
	while (1) {

		// polling
		int pollSize = polledFDs.size();
		int retval = poll(polledFDs.data(), polledFDs.size(),
				currentTimeout * 1000);

		if (retval == -1) {
			//err
		} else if (retval == 0) {
			//timeout
			// send new discovery
			sizeOfPacket = buildPacket(sendPacket, PACKET_DISCOVERY, UDPport,
					TCPport, hostname, username, NULL);

			// Send data to server
			Result = sendto(udpSocketFD, sendPacket, sizeOfPacket, 0,
					(struct sockaddr *) broadcastAddress,
					sizeof(struct sockaddr));
			if (0 > Result) {
				error("ERROR sending to server");
			}

			// increase timeout

			currentTimeout *= 2;
			if (currentTimeout > maxTimeout) {
				currentTimeout = maxTimeout;
			}

		} else {
			if (polledFDs[0].revents & POLLIN) { // stdin
				int ch = getch();
				WINDOW * currentWindow;
				struct Peer * currentPeer = NULL;
				if (ch >= ' ' && ch <= '~') {
					wechochar(typeWindow, ch);
					stdInBuff.push_back(ch);
				} else {

					switch (ch) {
					case '\n':
						if (stdInBuff.size() != 0) {
							//write to window
							if (currentPeerIndex == -1) {
								//currentPeer = peers.at(0);
								currentWindow = DEFAULT_CHAT_WINDOW;
							} else {
								currentPeer = peers.at(currentPeerIndex);
								currentWindow = currentPeer->p->win;
							}
							wclear(typeWindow);
							box(typeWindow, 0, 0);
							wmove(typeWindow, 1, 1);
							wrefresh(typeWindow);
							mvwaddstr(currentWindow, currentWindow->_cury + 1,
									1, " Me: ");
							mvwaddnstr(currentWindow, currentWindow->_cury,
									1 + strlen(" ME: "), stdInBuff.data(),
									stdInBuff.size());
							wrefresh(currentWindow);

							// writing to tcp socket
							if (currentPeer) {
								Result = send(currentPeer->socketFD,
										stdInBuff.data(), stdInBuff.size(), 0);

								if (0 > Result) {
									error("ERROR writing to socket");
								}
							}
							stdInBuff.clear();

						}
						break;

					case KEY_BACKSPACE: //ASCII for backspace char
						if (stdInBuff.size() != 0) {
							wclear(typeWindow);
							box(typeWindow, 0, 0);
							stdInBuff.pop_back();
							mvwaddnstr(typeWindow, 1, 1, stdInBuff.data(),
									stdInBuff.size());
							wrefresh(typeWindow);
						}
						break;

					case KEY_UP:
						if (currentPeerIndex > 0) {
							wattron(peersWindow, COLOR_PAIR(1));
							mvwaddstr(peersWindow, currentPeerIndex + 1, 2,
									peers.at(currentPeerIndex)->username);
							currentPeerIndex--;
							wattron(peersWindow, COLOR_PAIR(2));
							mvwaddstr(peersWindow, currentPeerIndex + 1, 2,
									peers.at(currentPeerIndex)->username);
							wattron(peersWindow, COLOR_PAIR(1));
							wrefresh(peersWindow);
							top_panel(peers.at(currentPeerIndex)->p);
							update_panels();
							doupdate();
						}

						break;

					case KEY_DOWN:
						if (currentPeerIndex < (int) peers.size() - 1) {
							if (currentPeerIndex > -1) {
								wattron(peersWindow, COLOR_PAIR(1));
								mvwaddstr(peersWindow, currentPeerIndex + 1, 2,
										peers.at(currentPeerIndex)->username);
							}
							currentPeerIndex++;
							wattron(peersWindow, COLOR_PAIR(2));
							mvwaddstr(peersWindow, currentPeerIndex + 1, 2,
									peers.at(currentPeerIndex)->username);
							wattron(peersWindow, COLOR_PAIR(1));
							wrefresh(peersWindow);
							top_panel(peers.at(currentPeerIndex)->p);
							update_panels();
							doupdate();
						}

						break;
					default:
						//wprintw(typeWindow, "0x%x", ch );
						break;
					}
				}

			} else if (polledFDs[1].revents & POLLIN) { //UDPSocket
				//zero out receive pkt to prevent overlapping
				bzero(receivePacket, sizeof(struct Packet));

				// Receive message from client
				Result = recvfrom(udpSocketFD, receivePacket,
						sizeof(struct Packet), 0,
						(struct sockaddr *) fromAddress, &fromAddressLength);
				if (0 > Result) {
					error("ERROR receive from client UDP");
				}

				if (memcmp(sendPacket, receivePacket, sizeOfPacket) == 0) {
					//sent packet is the received packet
					//must be self-discovery so return to polling
					continue;

				} else {
					// received new packet
					uint16_t opCode = ntohs(receivePacket->packetType.type);
					//					printf("this is the opCode %d\n", opCode);

					if (opCode == PACKET_REPLY) {
						//add peer to known peers
						struct Peer* newPeer = createPeer(receivePacket,
								fromAddress);
						addPeer(newPeer);

						// disable timeout to terminate sending of discovery packets
						currentTimeout = -1;

					} else if (opCode == PACKET_DISCOVERY) {
						// send reply

						// build reply packet
						sizeOfPacket = buildPacket(sendPacket, PACKET_REPLY,
								UDPport, TCPport, hostname, username, NULL);
						// Send data to server
						Result = sendto(udpSocketFD, sendPacket, sizeOfPacket,
								0, (struct sockaddr *) fromAddress,
								sizeof(struct sockaddr));
						if (0 > Result) {
							error("ERROR sending to server UDP");
						}

						// if new peer
						struct Peer* newPeer = createPeer(receivePacket,
								fromAddress);
						addPeer(newPeer);
						currentTimeout = -1;

					} else if (opCode == PACKET_CLOSING) {

						struct Peer* peer = createPeer(receivePacket,
								fromAddress);
						for (int i = 0; i < peers.size(); i++) {
							if (strcmp(peer->username, peers.at(i)->username)
									== 0
									&& strcmp(peer->hostname,
											peers.at(i)->hostname) == 0
									&& peer->tcpPort == peers.at(i)->tcpPort
									&& peer->udpPort == peers.at(i)->udpPort) {
								peers.erase(peers.begin() + i);
								remove_peer_from_window();
							}
						}
						if (peers.size() == 0)
							currentTimeout = DEFAULT_INIT_TIMEOUT;

					}

					// wait to receive tcp connection

				}
			} else if (polledFDs[2].revents & POLLIN) { //TCP SOCKEt
				//printf("tcp request accpected\n");
				int new_socket;

				int addrlen = sizeof(ServerAddressTCP);

				if ((new_socket = accept(tcpSocketFD,
						(struct sockaddr *) &ServerAddressTCP,
						(socklen_t*) &addrlen)) < 0) {
					perror("accept");
					exit(EXIT_FAILURE);
				}

				addToPolledFD(new_socket);

			} else {

				// poll the rest in polledFD

				for (int i = 3; i < polledFDs.size(); i++) {
					if (polledFDs[i].revents & POLLIN) {
						//printf("TCP connection was recieved\n");
						char Buffer[255];
						bzero(Buffer, 255);

						int Result = read(polledFDs[i].fd, Buffer, 255);

						if (0 > Result) {
							error("ERROR reading from socket");
						}
						WINDOW * currentWindow;
						if (currentPeerIndex == -1) {
							currentWindow = DEFAULT_CHAT_WINDOW;
						} else {
							currentWindow = peers.at(currentPeerIndex)->p->win;
						}
						mvwaddstr(currentWindow, currentWindow->_cury + 1, 1,
								" You: ");

						mvwaddnstr(currentWindow, currentWindow->_cury,
								1 + strlen(" You: "), Buffer, strlen(Buffer));
						wrefresh(currentWindow);
					}
				}

			}
		}
	}

	return 0;
}
void init_UI(){
	initscr();
	cbreak();
	keypad(stdscr, TRUE);
	keypad(peersWindow, TRUE);
	keypad(typeWindow, TRUE);
	keypad(DEFAULT_CHAT_WINDOW, TRUE);
	noecho();
	start_color();
	init_pair(1, COLOR_WHITE, COLOR_BLACK);
	init_pair(2, COLOR_BLACK, COLOR_WHITE);
	refresh();

	peersWindow = create_newwin(LINES, COLS/5, 0, 0);
	DEFAULT_CHAT_WINDOW = create_newwin(LINES*4/5, COLS*4/5, 0, COLS/5);
	typeWindow = create_newwin(LINES/5, COLS*4/5, LINES*4/5, COLS/5);
	wmove(typeWindow, 1, 1);
	wrefresh(typeWindow);


}

WINDOW *create_newwin(int height, int width, int starty, int startx)
{
	WINDOW *local_win;

	local_win = newwin(height, width, starty, startx);
	box(local_win, 0 , 0);

	wrefresh(local_win);

	return local_win;
}

void destroy_win(WINDOW *local_win)
{
	wborder(local_win, ' ', ' ', ' ',' ',' ',' ',' ',' ');
	wrefresh(local_win);
	delwin(local_win);
}

void add_peer_to_window(struct Peer * peer){
	mvwprintw(peersWindow, peers.size() + 1, 2, peer->username);
	wrefresh(peersWindow);

}

int makeUDPSocket(struct sockaddr_in *ServerAddress, uint16_t UDPport){
    // Create UDP/IP socket
    int SocketFileDescriptor;
    int BroadcastEnable = 1;
    int Result;

    SocketFileDescriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (0 > SocketFileDescriptor) {
        error("ERROR opening socket");
    }

    // Set UDP socket to enable broadcast
    Result = setsockopt(SocketFileDescriptor, SOL_SOCKET, SO_BROADCAST,
                        &BroadcastEnable, sizeof(BroadcastEnable));

    if (0 > Result) {
        close(SocketFileDescriptor);
        error("ERROR setting socket option");
    }

    // Setup ServerAddress data structure
    bzero(ServerAddress, sizeof(struct sockaddr));
    ServerAddress->sin_family = AF_INET;
    ServerAddress->sin_addr.s_addr = htonl(INADDR_ANY);
    ServerAddress->sin_port = htons(UDPport);


    // Binding socket to port
    if (0 > bind(SocketFileDescriptor, (struct sockaddr *)ServerAddress,
                 sizeof(struct sockaddr))) {
        error("ERROR on binding");
    }

    return SocketFileDescriptor;
}


int makeTCPSocket(struct sockaddr_in *ServerAddress, uint16_t TCPport){
    // Create TCP/IP socket
    int SocketFileDescriptor;

    SocketFileDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (0 > SocketFileDescriptor) {
        error("ERROR opening socket");
    }

    // Setup ServerAddress data structure
    bzero(ServerAddress, sizeof(struct sockaddr));
    ServerAddress->sin_family = AF_INET;
    ServerAddress->sin_addr.s_addr = INADDR_ANY;
    ServerAddress->sin_port = htons(TCPport);


    // Binding socket to port
    if (0 > bind(SocketFileDescriptor, (struct sockaddr *) ServerAddress,
                 sizeof(struct sockaddr))) {
        error("ERROR on binding");
    }

    // listens with a queue of 5
    listen(SocketFileDescriptor, 5);

    return SocketFileDescriptor;
}

void SignalHandler(int param) {
    //TODO close all sockets
    //close(SocketFileDescriptor);
    struct Packet *pkt2send = (struct Packet*)malloc(sizeof(struct Packet));
    int Result;
    int packetSize = buildPacket(pkt2send, PACKET_CLOSING, UDPport, TCPport, hostname, username, NULL);


    Result = sendto(udpSocketFD, pkt2send, packetSize, 0,
                    (struct sockaddr *)broadcastAddress, sizeof(struct sockaddr));

    if (0 > Result) {
        error("ERROR sending to server");
    }

	endwin();
    exit(0);
}

int addToPolledFD(int filedescriptor){
    struct pollfd newPollFD;
    newPollFD.fd = filedescriptor;
    newPollFD.events = POLLIN;
    newPollFD.revents = 0;
    polledFDs.push_back(newPollFD);
    return polledFDs.size();

}

//returns the size of packet
int buildPacket(struct Packet* packet, uint16_t opCode, uint16_t udp, uint16_t tcp,
                char * hostname, char * username, char* message) {

    if (packet) {
        strncpy((char*)packet->signature, "P2PI", SIGNATURE_LENGTH);
        packet->packetType.type = htons(opCode);

        if (opCode <= 3) {

            packet->packetType.udpMessage.UDPPort = htons(udp);
            packet->packetType.udpMessage.TCPPort = htons(tcp);

            strcpy((char*)packet->packetType.udpMessage.hostnameUsername, hostname);
            strcat((char*)packet->packetType.udpMessage.hostnameUsername, "t");
            strcat((char*)packet->packetType.udpMessage.hostnameUsername, username);
            packet->packetType.udpMessage.hostnameUsername[strlen(hostname)] = '\0';

            return SIGNATURE_LENGTH + sizeof(packet->packetType.udpMessage.type) +
                    sizeof(packet->packetType.udpMessage.UDPPort) +
                    sizeof(packet->packetType.udpMessage.TCPPort) +
                    strlen(hostname) + 1 + strlen(username) + 1;
        } else if(opCode == 4) {
            strcpy((char*)packet->packetType.establishCom.username, username);
            return SIGNATURE_LENGTH + sizeof(packet->packetType.type) + strlen(username) + 1;

        } else if(opCode <=7){
            return SIGNATURE_LENGTH + sizeof(packet->packetType.type);
        } else if(opCode == 9){
            strcpy((char*)packet->packetType.data.message, message);
            return SIGNATURE_LENGTH + sizeof(packet->packetType.type) + strlen(message) + 1;
        } else if(opCode == 10){
            return SIGNATURE_LENGTH + sizeof(packet->packetType.type);

        }
    }
    return -1;

}


void error(const char *message) {
    perror(message);
    exit(0);
}

struct Peer* createPeer(struct Packet* pkt, sockaddr_in* fromAddress){
    struct Peer *newPeer = (struct Peer*)malloc(sizeof(struct Peer));
    newPeer->ipv4Address = ntohl(fromAddress->sin_addr.s_addr);
    newPeer->udpPort = ntohs(pkt->packetType.udpMessage.UDPPort);
    newPeer->tcpPort = ntohs(pkt->packetType.udpMessage.TCPPort);

    parseHostnameUsername((char*)pkt->packetType.udpMessage.hostnameUsername,
                          (char*)newPeer->hostname, (char*)newPeer->username);
    WINDOW * newWin = create_newwin(LINES*4/5, COLS*4/5, 0, COLS/5);
    mvwprintw(newWin, 0, 10, " %s ", newPeer->username);
    newPeer->p = new_panel(newWin);

    // make TCP Peer
    if((1 > newPeer->tcpPort)||(65535 < newPeer->tcpPort)){
        fprintf(stderr,"Port %d is an invalid port number\n",newPeer->tcpPort);
        exit(0);
    }

    newPeer->socketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(0 > newPeer->socketFD){
        error("ERROR opening socket");
    }

    // Convert/resolve host name
    newPeer->server = gethostbyname(newPeer->hostname);
    if(NULL == newPeer->server){
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    // Setup ServerAddress data structure
    bzero((char *) &newPeer->serverAddress, sizeof(newPeer->serverAddress));
    newPeer->serverAddress.sin_family = AF_INET;
    bcopy((char *)newPeer->server->h_addr, (char *)&newPeer->serverAddress.sin_addr.s_addr, newPeer->server->h_length);
    newPeer->serverAddress.sin_port = htons(newPeer->tcpPort);

    if(0 > connect(newPeer->socketFD, (struct sockaddr *)&newPeer->serverAddress, sizeof(newPeer->serverAddress))){
        error("ERROR connecting");
    }

    return newPeer;

}

void remove_peer_from_window(){
	wclear(peersWindow);
	box(peersWindow, 0 , 0);
	for(int i = 0; i < peers.size(); i++){
		mvwprintw(peersWindow, i+1, 1, peers.at(i)->username);
	}
	wrefresh(peersWindow);
}

void addPeer(struct Peer *peer){
    //window->addPeer(peer);
    add_peer_to_window(peer);
	peers.push_back(peer);
}

int parseHostnameUsername(char* origString, char* hostname, char* username){
    if(hostname == NULL || username == NULL){
        return -1;
    }
    strcpy(hostname, origString);
    strcpy(username, strchr(origString, '\0') + 1);
    if (username == NULL || strlen(username) == 0) {
        return -1;
    }
    return 0;
}
