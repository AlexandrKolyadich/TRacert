#pragma warning( disable : 4996)
#include <stdio.h> 
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#pragma comment(lib, "ws2_32.lib")
using namespace std;
#define DEFAULT_PACKET_SIZE 40
typedef struct ICMPheader
{
	unsigned char	Type;
	unsigned char	Code;
	unsigned short	Checksum;
	unsigned short	Id;
	unsigned short	nOfSequence;
} ICMPHead, *ICMPHeadd;
typedef struct IPHeader {
	BYTE ver_n_len;
	BYTE srv_type;
	USHORT total_len;
	USHORT pack_id;
	USHORT flags : 3;
	USHORT offset : 13;
	BYTE TTL;
	BYTE proto;
	USHORT checksum;
	UINT source_ip;
	UINT dest_ip;
} IPHeader, *IPHeaderr;
typedef struct _PacketSets {
	struct sockaddr_in *source;
	DWORD ping;
} PacketSets, *PacketSetss;

USHORT calcCheckSum(USHORT *packet) {
	ULONG checksum = 0;
	int size = 40;
	while (size > 1) {
		checksum += *(packet++);
		size -= sizeof(USHORT);
	}
	if (size) checksum += *(UCHAR *)packet;

	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);

	return (USHORT)(~checksum);
}

void PingPackets(ICMPHeadd sendHdr, byte sequence) {
	sendHdr->Type = 8;
	sendHdr->Code = 0;
	sendHdr->Checksum = 0;
	sendHdr->Id = 1;
	sendHdr->nOfSequence = sequence;

	sendHdr->Checksum = calcCheckSum((USHORT *)sendHdr);
}
int PingRequest(SOCKET socket, ICMPHeadd Buf, const struct sockaddr_in *dest)
{
	int Res = sendto(socket, (char *)Buf, DEFAULT_PACKET_SIZE, 0, (struct sockaddr *)dest, sizeof(struct sockaddr_in));// отправляет пакет

	if (Res == SOCKET_ERROR)
		return Res;
	return 0;
}
int Report(IPHeaderr ipHdr, struct sockaddr_in *source, USHORT arg, ULONG sendingTime, PacketSetss decodeResult)
{
	DWORD arrivalTime = GetTickCount();

	unsigned short ipHdrLen = (ipHdr->ver_n_len & 0x0F) * 4;// задаем смещение чтобы обратиться к участку памяти 
	ICMPHeadd icmpHdr = (ICMPHeadd)((char *)ipHdr + ipHdrLen);

	if (icmpHdr->Type == 11) {//ttl Expired
		IPHeaderr requestIPHdr = (IPHeaderr)((char *)icmpHdr + 8);
		unsigned short requestIPHdrLen = (requestIPHdr->ver_n_len & 0x0F) * 4;

		ICMPHeadd requestICMPHdr = (ICMPHeadd)((char *)requestIPHdr + requestIPHdrLen);

		if (requestICMPHdr->nOfSequence == arg) {
			decodeResult->source = source;
			decodeResult->ping = arrivalTime - sendingTime;
			return 1;
		}
	}

	if (icmpHdr->Type == 0) {//last hop 
		if (icmpHdr->nOfSequence == arg) {
			decodeResult->source = source;
			decodeResult->ping = arrivalTime - sendingTime;
			return 2;
		}
	}

	return -1;
}
int PingPacketGet(SOCKET socket, IPHeaderr recvBuf, struct sockaddr_in *source)
{
	int srcLen = sizeof(struct sockaddr_in);

	fd_set theOneSocket; // структура для селекта
	theOneSocket.fd_count = 1;
	theOneSocket.fd_array[0] = socket;
	struct timeval tWait = { 10, 0 };

	int selectRes;
	if ((selectRes = select(0, &theOneSocket, NULL, NULL, &tWait)) == 0) return 0; // time-out
	if (selectRes == SOCKET_ERROR) return 1;

	return recvfrom(socket, (char *)recvBuf, 1024, 0, (struct sockaddr *)source, &srcLen);//прога повисает пока не пришел ответ 
}
void Out(PacketSetss sets, BOOL IP)
{
	printf("%6d", sets->ping);//печатает время

	if (IP) {//если последнее
		char *Addr = inet_ntoa(sets->source->sin_addr);
		if (Addr != NULL) {
			printf("\t%s", Addr);
		}
		char buf[NI_MAXHOST];
		if (!getnameinfo((struct sockaddr *)(sets->source), sizeof(struct sockaddr_in), buf, sizeof(buf), // получает имя хоста 
			NULL, 0, NI_NAMEREQD))
			printf(" %s", buf);
	}
}

int main(int argc, char *argv[])
{
	printf("Way to\n");
	printf("Max number of jumps 30:\n");
	BOOL endOfTracert = FALSE, printIP;
	ICMPHead sendHdr;
	WSADATA wsaData;//  структура которая используется для инициализации сокета
	WORD DLLVersion = MAKEWORD(2, 2); // запрашиваемая версия библиотеки winsock
	if (WSAStartup(DLLVersion, &wsaData) != 0) { // если библиотека загрузилась удачно то она вернет 0; первый параметр -  версия библ
		std::cout << "error" << std::endl;		// второй параметр - ссылка на структуру 
		exit(1);								//WSAStartup - функция для загрузки библиотеки 
	}
	int TTL = 0;
	int numberOfJump = 1;
	UINT destAddr = inet_addr(argv[1]); // преобразует адрес в набор байтов
	SOCKADDR_IN dest, source; // стркуктура для заполнения адреса сокета
	ICMPHeadd BufToSend = (ICMPHeadd)malloc(DEFAULT_PACKET_SIZE);
	IPHeaderr BufToGet = (IPHeaderr)malloc(1024);
	SOCKET socket = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0);//сырые сокеты // afinet создает сеть
	if (socket == INVALID_SOCKET) {
		wprintf(L"socket failed with error %d\n", WSAGetLastError());
		return 1;
	}
	dest.sin_addr.s_addr = destAddr; // в этой структуре хранится айпи адрес  
	dest.sin_family = AF_INET;// семейство протоколов, для интернет-протоколов исппользуется эта константа AF_INET IPV4
	PacketSets sets;// в этой структуре лежит пинг
	byte arg = 1;// 
	int hops = 30;
	ULONG Time;
	BOOL stateError = FALSE;
	do {
		TTL++;
		setsockopt(socket, IPPROTO_IP, IP_TTL, (char *)&TTL, sizeof(int));// настройка опций пакета меняем ттл 
		BOOL flagPrintIP = FALSE;
		printf("%3d.", numberOfJump++);
		int counterPingPack = 0;
		while (counterPingPack < 3) {
			if (counterPingPack == 3)
				flagPrintIP = TRUE;
			PingPackets(BufToSend, arg);// инициализация пакета пинг
			Time = GetTickCount();// отправляемое времся
			PingRequest(socket, BufToSend, &dest);//
			int resultReq;
			int res = -1; // error;

			resultReq = PingPacketGet(socket, BufToGet, &source);//получуение пинг
			if (resultReq == 0) {
				printf(" *");
			}
			else {
				res = Report(BufToGet, &source, arg, Time, &sets);// для того чтобы понять ошибочный пакет или последний
				if (res == -1) {
					printf("*");
				}
				else {
					if (res == 2) {
						endOfTracert = TRUE;
					}
					Out(&sets, flagPrintIP);//
					//printf("sdfsdf");
				}
			}
			counterPingPack++;
		}
		printf("\n");
	} while (!endOfTracert && (TTL != 30));
	system("pause");
}