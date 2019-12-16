typedef struct {
  uint8_t packetInfo;     // 0
  uint32_t packetNumber;  // 1
  uint64_t timeStamp;     // 5  (in 32 us unit ?)
  uint16_t payloadLength; // 13 (packetLen+1)
  uint8_t packetLen;      // 15
  uint8_t data[];
} __attribute__((__packed__)) tiudp;

void initSend(char *host);
void sendUDP(tiudp *data);
