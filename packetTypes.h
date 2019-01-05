/*
 * PacketTypes.h
 *
 *  Created on: May 8, 2018
 *      Author: amazor
 */


#ifndef PACKETTYPES_H_
#define PACKETTYPES_H_
#include <stdint.h>
#include <limits.h>

#define SIGNATURE_LENGTH 4
#define MAX_MESSAGE_LENGTH 256

#define PACKET_DISCOVERY 1
#define PACKET_REPLY 2
#define PACKET_CLOSING 3
#define PACKET_ESTABLISH_COM 4
#define PACKET_ACK_COM 5
#define PACKET_USER_UNAVAILABLE 6
#define PACKET_REQUEST_USER_LIST 7
#define PACKET_USER_LIST_REPLY 8
#define PACKET_MESSAGE 9
#define PACKET_DISCONTUE_COM 10


struct Packet{
	uint8_t signature[SIGNATURE_LENGTH];


	union PacketType{
		uint16_t type;

		struct UDPMessagePacket{
			uint16_t type;
			uint16_t UDPPort;
			uint16_t TCPPort;
			uint8_t hostnameUsername[_POSIX_HOST_NAME_MAX + 1 + _POSIX_LOGIN_NAME_MAX + 1];
		} udpMessage;

		struct EstablishCommunicationPacket{
			uint16_t type;
			uint8_t username[_POSIX_LOGIN_NAME_MAX + 1];
		} establishCom;

		struct AckCommunicationPacket{
			uint16_t type;
		} ackCom;

		struct UserUnavailablePacket{
			uint16_t type;
		}usrUnavailable;

		struct RequestUserListPacket{
			uint16_t type;
		}rqstUsrList;

		struct DataPacket{
			uint16_t type;
			uint8_t message[MAX_MESSAGE_LENGTH + 1];
		}data;

		struct DiscontinueCommunicationPacket{
			uint16_t type;
		}discontinueCom;

	}packetType;

};



#endif /* PACKETTYPES_H_ */
