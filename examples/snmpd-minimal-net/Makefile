ifndef TARGET
  TARGET=minimal-net
endif

PROJECT=snmp-server

UIP_CONF_IPV6=1
APPS=snmpd

CONTIKI=../..

include $(CONTIKI)/Makefile.include

all:
	make TARGET=minimal-net MIB_INIT=mib-init.c $(PROJECT).minimal-net

clean:
        make TARGET=minimal-net clean
	rm -rf obj_native
        rm symbols.c symbols.h
        rm -rf obj_minimal-net
        rm $(PROJECT).minimal-net
