#include "main.h"
#include <map>
#include <cstdlib>

map<Mac, info> m;

void usage(void)
{
    puts("syntax : airodump <interface>");
    puts("sample : airodump mon0");
}

void printInfo()
{
    system("clear");
    printf(" BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID\n");
    for (auto temp : m)
    {
        printf(" ");
        printf("%s", string(temp.first).c_str());
        printf("           %03d                ", temp.second.beacons);
        printf("%d", temp.second.channel);
        printf("                        ");
        printf("%s", temp.second.essid);
        printf("\n");
    }
}

void airodump(const u_char *packet, int length)
{
    radiotapHdr *rtHdr = (radiotapHdr *)packet;
    beaconFrame *bcnFrame = (beaconFrame *)(packet + rtHdr->it_len);
    u_int8_t *tag = (u_int8_t *)(packet + rtHdr->it_len + sizeof(beaconFrame) + FIXED_PARAM_SIZE);

    if (bcnFrame->type != 0x80)
        return;

    if (m.find(bcnFrame->bssid) != m.end())
    {
        m[bcnFrame->bssid].beacons++;
    }
    else
    {
        info newInfo;
        newInfo.bssid = bcnFrame->bssid;
        newInfo.beacons = 1;
        newInfo.data = 0;
        newInfo.channel = 0;
        int idx = rtHdr->it_len + sizeof(beaconFrame) + FIXED_PARAM_SIZE;
        while (idx < length)
        {
            int tagno = packet[idx++];
            int taglen = packet[idx++];
            if (idx + taglen >= length)
                break;
            if (tagno == 0)
            {
                memcpy(newInfo.essid, packet + idx, taglen);
                newInfo.essid[taglen] = '\0';
            }
            else if (tagno == 3)
            {
                newInfo.channel = packet[idx];
            }
            idx += taglen;
        }
        m[bcnFrame->bssid] = newInfo;
    }
    printInfo();
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
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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
        airodump(packet, header->caplen);
    }
    pcap_close(handle);
    return 0;
}
