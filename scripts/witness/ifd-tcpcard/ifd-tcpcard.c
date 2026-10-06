/* A PC/SC reader driver whose card is at the other end of a TCP socket,
   speaking canokey-core apdu-replay's line protocol through cardsim.py:
   one hex APDU per line out, "RESP <SW><DATA>" back. DEVICENAME in
   reader.conf is the port on 127.0.0.1. */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ifdhandler.h>

static const UCHAR ATR[] = {0x3B, 0xF7, 0x11, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x65,
                            0x43, 0x61, 0x6E, 0x6F, 0x6B, 0x65, 0x79, 0x99};
static int sock = -1;
static FILE *in;

static RESPONSECODE open_port(int port) {
	sock = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = {0};
	a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(0x7f000001);
	if (connect(sock, (struct sockaddr *)&a, sizeof a) != 0) { close(sock); sock = -1; return IFD_COMMUNICATION_ERROR; }
	in = fdopen(dup(sock), "r");
	return IFD_SUCCESS;
}

RESPONSECODE IFDHCreateChannelByName(DWORD Lun, LPSTR DeviceName) { (void)Lun; return open_port(atoi(DeviceName)); }
RESPONSECODE IFDHCreateChannel(DWORD Lun, DWORD Channel) { (void)Lun; return open_port(Channel ? (int)Channel : 35963); }
RESPONSECODE IFDHCloseChannel(DWORD Lun) { (void)Lun; if (in) fclose(in); if (sock >= 0) close(sock); sock = -1; in = NULL; return IFD_SUCCESS; }

RESPONSECODE IFDHGetCapabilities(DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value) {
	(void)Lun;
	switch (Tag) {
	case TAG_IFD_ATR: memcpy(Value, ATR, sizeof ATR); *Length = sizeof ATR; return IFD_SUCCESS;
	case TAG_IFD_SLOTS_NUMBER: *Value = 1; *Length = 1; return IFD_SUCCESS;
	case TAG_IFD_SIMULTANEOUS_ACCESS: *Value = 1; *Length = 1; return IFD_SUCCESS;
	case TAG_IFD_THREAD_SAFE: *Value = 0; *Length = 1; return IFD_SUCCESS;
	default: return IFD_ERROR_TAG;
	}
}
RESPONSECODE IFDHSetCapabilities(DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value) { (void)Lun; (void)Tag; (void)Length; (void)Value; return IFD_NOT_SUPPORTED; }
RESPONSECODE IFDHSetProtocolParameters(DWORD Lun, DWORD Protocol, UCHAR Flags, UCHAR PTS1, UCHAR PTS2, UCHAR PTS3) {
	(void)Lun; (void)Protocol; (void)Flags; (void)PTS1; (void)PTS2; (void)PTS3; return IFD_SUCCESS;
}

static int line(const char *text, char *answer, size_t size) {
	size_t n = strlen(text);
	if (write(sock, text, n) != (ssize_t)n) return -1;
	return fgets(answer, (int)size, in) ? 0 : -1;
}

RESPONSECODE IFDHPowerICC(DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength) {
	(void)Lun;
	char answer[64];
	if (Action == IFD_POWER_DOWN) {
		if (line("!POWEROFF\n", answer, sizeof answer) < 0) return IFD_COMMUNICATION_ERROR;
		*AtrLength = 0;
		return IFD_SUCCESS;
	}
	memcpy(Atr, ATR, sizeof ATR); *AtrLength = sizeof ATR;
	return IFD_SUCCESS;
}

RESPONSECODE IFDHTransmitToICC(DWORD Lun, SCARD_IO_HEADER SendPci, PUCHAR TxBuffer, DWORD TxLength,
                               PUCHAR RxBuffer, PDWORD RxLength, PSCARD_IO_HEADER RecvPci) {
	(void)Lun; (void)SendPci; (void)RecvPci;
	static char out[2 * 70000], answer[2 * 70000];
	for (DWORD i = 0; i < TxLength; i++) sprintf(out + 2 * i, "%02X", TxBuffer[i]);
	strcpy(out + 2 * TxLength, "\n");
	if (line(out, answer, sizeof answer) < 0 || strncmp(answer, "RESP ", 5)) return IFD_COMMUNICATION_ERROR;
	char *hex = answer + 5;
	size_t n = strcspn(hex, "\r\n") / 2;   /* SW first, then the data */
	if (n < 2 || n > *RxLength) return IFD_COMMUNICATION_ERROR;
	unsigned v;
	for (size_t i = 2; i < n; i++) { sscanf(hex + 2 * i, "%2x", &v); RxBuffer[i - 2] = (UCHAR)v; }
	sscanf(hex, "%2x", &v); RxBuffer[n - 2] = (UCHAR)v;
	sscanf(hex + 2, "%2x", &v); RxBuffer[n - 1] = (UCHAR)v;
	*RxLength = (DWORD)n;
	return IFD_SUCCESS;
}

RESPONSECODE IFDHControl(DWORD Lun, DWORD dwControlCode, PUCHAR TxBuffer, DWORD TxLength, PUCHAR RxBuffer,
                         DWORD RxLength, LPDWORD pdwBytesReturned) {
	(void)Lun; (void)dwControlCode; (void)TxBuffer; (void)TxLength; (void)RxBuffer; (void)RxLength;
	*pdwBytesReturned = 0; return IFD_ERROR_NOT_SUPPORTED;
}
RESPONSECODE IFDHICCPresence(DWORD Lun) { (void)Lun; return sock >= 0 ? IFD_ICC_PRESENT : IFD_ICC_NOT_PRESENT; }
