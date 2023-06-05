#include <iostream>
#include <netinet/in.h>
#include <pcap.h>
#include <map>
#include <cstdlib>
#include "radiotap.h"
#include "beacon.h"
#include "mac.h"

#define FIXED_PARAM_SIZE 12
using namespace std;

typedef struct info
{
    Mac bssid;
    int beacons;
    char ENC[9];
    char essid[128];
    int channel;
} info;