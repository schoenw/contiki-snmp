#include "contiki.h"
#include "dev/leds.h"

PROCESS(b, "b");
AUTOSTART_PROCESSES(&b);

PROCESS_THREAD(b, ev, data) {
	PROCESS_EXITHANDLER(goto exit;)
	PROCESS_BEGIN();
	static int index = 0;
	while(1) {
		static struct etimer et;
		etimer_set(&et, CLOCK_SECOND/4);
		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
		if (index == 0) {
			leds_toggle(LEDS_BLUE);
		}
		if (index % 2 == 0) {
			leds_toggle(LEDS_GREEN);
		}
		leds_toggle(LEDS_RED);
		index = (index + 1) % 4;
	}

	exit:
		PROCESS_END();
}
