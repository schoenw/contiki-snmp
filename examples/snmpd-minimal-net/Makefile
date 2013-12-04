ifndef TARGET
  TARGET=minimal-net
endif
ifndef PROJECT
  PROJECT=snmp-server
endif

all:
	${MAKE} -f Makefile.snmp TARGET=$(TARGET) MIB_INIT=mib-init.c $(PROJECT).minimal-net

clean:
	${MAKE} -f Makefile.snmp TARGET=$(TARGET) clean
	rm -rf obj_native
	rm symbols.c symbols.h
	rm -rf obj_minimal-net
	rm $(PROJECT).minimal-net
