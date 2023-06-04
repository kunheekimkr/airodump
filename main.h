#include <iostream>
#include <netinet/in.h>
#include <pcap.h>
#include "mac.h"

#define FIXED_PARAM_SIZE 12
using namespace std;

// Source: https://www.radiotap.org/
typedef struct ieee80211_radiotap_header
{
    u_int8_t it_version; /* set to 0 */
    u_int8_t it_pad;
    u_int16_t it_len;     /* entire length */
    u_int32_t it_present; /* fields present */
} __attribute__((__packed__)) radiotapHdr;

typedef struct ieee80211_beacon_frame
{
    u_int8_t type;
    u_int8_t flags;
    u_int16_t duration;
    Mac dest;
    Mac src;
    Mac bssid;
    u_int16_t seq;
} __attribute__((__packed__)) beaconFrame;

typedef struct info
{
    Mac bssid;
    int beacons;
    int data;
    char essid[128];
    int channel;
} info;