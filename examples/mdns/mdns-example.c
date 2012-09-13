#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

#include "mac.h"
#include "mdns.h"

#include <string.h>

AUTOSTART_PROCESSES(&mdns_querier_process, &mdns_processor_process);
