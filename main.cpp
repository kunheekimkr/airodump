#include "main.h"

void usage(void)
{
    puts("syntax : airodump <interface>");
    puts("sample : airodump mon0");
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return 0;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device(%s)(%s)\n", dev, errbuf);
        return -1;
    }

    while (1)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            break;
        }

        // Main Logic
    }
}
