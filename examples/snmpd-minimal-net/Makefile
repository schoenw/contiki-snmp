TARGET=native
PROJECT=snmp-server

UIP_CONF_IPV6=1
APPS=snmpd 

CONTIKI=../..

include $(CONTIKI)/Makefile.include

#CFLAGS   += -DENABLE_SNMPv1
#CFLAGS   += -DENABLE_SNMPv3

common:

minimal-net: common
	make TARGET=minimal-net MIB_INIT=mib-init.c $(PROJECT).minimal-net

minimal-net-mib: common
	make TARGET=minimal-net MIB_INIT=mib-init-raven.c $(PROJECT).minimal-net

raven: 	
	make TARGET=avr-raven MIB_INIT=mib-init.c $(PROJECT).elf
	avr-objcopy -O ihex -R .eeprom -R .fuse -R .signature $(PROJECT).elf $(PROJECT).hex
	avr-size -C --mcu=atmega1284p $(PROJECT).elf
	rm -rf obj_native

raven-mib: 	
	make TARGET=avr-raven MIB_INIT=mib-init-raven.c $(PROJECT).elf
	avr-objcopy -O ihex -R .eeprom -R .fuse -R .signature $(PROJECT).elf $(PROJECT).hex
	avr-size -C --mcu=atmega1284p $(PROJECT).elf
	rm -rf obj_native

raven-empty-mib:
	make TARGET=avr-raven MIB_INIT=mib-init-empty.c $(PROJECT).elf
	avr-objcopy -O ihex -R .eeprom -R .fuse -R .signature $(PROJECT).elf $(PROJECT).hex
	avr-size -C --mcu=atmega1284p $(PROJECT).elf
	rm -rf obj_native

cl-all:
	make TARGET=avr-raven clean
	make TARGET=minimal-net clean
	rm -rf obj_native
	rm symbols.c symbols.h $(PROJECT).elf $(PROJECT).hex
	rm -rf obj_avr-raven
	rm -rf obj_minimal-net
	rm $(PROJECT).minimal-net
	
cl-minnet:
	make TARGET=minimal-net clean
	rm -rf obj_native
	rm symbols.c symbols.h
	rm -rf obj_minimal-net
	rm $(PROJECT).minimal-net

cl-raven:
	make TARGET=avr-raven clean
	rm -rf obj_native
	rm symbols.c symbols.h $(PROJECT).elf $(PROJECT).hex
	rm -rf obj_avr-raven

upload:
	avrdude -p m1284p -c jtag2 -P usb -v -F -e -U flash:w:"./$(PROJECT).hex"

run:
	sudo ./snmp-server.minimal-net
