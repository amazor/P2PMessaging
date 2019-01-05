/*
 * peerInfo.h
 *
 *  Created on: May 9, 2018
 *      Author: amazor
 */

#ifndef PEERINFO_H_
#define PEERINFO_H_
#include <stdint.h>
#include <ncurses.h>
#include <panel.h>

struct Peer {
    char username[_POSIX_LOGIN_NAME_MAX + 1];
    char hostname[_POSIX_HOST_NAME_MAX + 1];
    uint16_t udpPort;
    uint16_t tcpPort;
    uint32_t ipv4Address;
    PANEL * p;
    int socketFD; 
    struct sockaddr_in serverAddress; 
    struct hostent *server; 
};






#endif /* PEERINFO_H_ */
