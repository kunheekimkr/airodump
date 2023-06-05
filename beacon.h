#include <netinet/in.h>
#include "mac.h"

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