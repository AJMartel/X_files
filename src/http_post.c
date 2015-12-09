#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
// Example how you can send http POST without use Curl,PICO,ACE etc....

int main()
{
	WSAData wsaData_;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData_) != 0)
		return 0;

	struct addrinfo * sResult, sHints;

	RtlZeroMemory(&sHints, sizeof(sHints));

	sHints.ai_socktype = SOCK_STREAM;
	sHints.ai_protocol = IPPROTO_TCP;
	sHints.ai_flags = AI_PASSIVE;
	sHints.ai_family = AF_UNSPEC;  //IPV6 or IPV4

	int iResult = getaddrinfo("www.target.com", "80", &sHints, &sResult);

	if (iResult != 0)
	{
		WSACleanup();
		return 0;
	}
		
	SOCKET sSocket = socket(sResult->ai_family, sResult->ai_socktype, sResult->ai_protocol);

	if (sSocket != INVALID_SOCKET)
	{
		iResult = connect(sSocket, sResult->ai_addr, (INT)sResult->ai_addrlen);

		if (iResult == SOCKET_ERROR)
		{
			closesocket(sSocket);
			sSocket = 0;
		}
	}

	char head_tosend[] =
		"POST %s HTTP/1.0\r\n"
		"Host: %s\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Encoding: binary\r\n"
		"Content-Length: %i\r\n"
		"Connection: close\r\n"
		"\r\n";

	char sPost[] = "a=VALUE1&b=VALUE2";

	char sHeader[sizeof(head_tosend) + 100];
	char sRecv[1000];

	if (sSocket != 0)
	{
		RtlZeroMemory(sHeader, sizeof(sHeader));
		RtlZeroMemory(sRecv, sizeof(sRecv));

		int iDataLen = lstrlenA(sPost), iHeaderLen = wsprintfA(sHeader, head_tosend, "/index.php?page", "www.target.com", iDataLen);

		if (iHeaderLen > 0)
		{
			if (send(sSocket, (Pchar)sHeader, iHeaderLen, 0) != SOCKET_ERROR) //Header
			{
				if (send(sSocket, (Pchar)sPost, iDataLen, 0) != SOCKET_ERROR) //Data
				{
					if (recv(sSocket, (Pchar)sRecv, sizeof(sRecv)-1, 0) != SOCKET_ERROR)
						MessageBoxA(0, sRecv, 0, 0);
				}
			}
		}

		closesocket(sSocket);
	}

	freeaddrinfo(sResult);

	WSACleanup();

	return 0;
}

