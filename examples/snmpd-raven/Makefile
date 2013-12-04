ifndef TARGET
  TARGET=avr-raven
  MCU=atmega1284p
endif
ifndef WEBDIR
 OUTFILE=webserver6-$(TARGET)
else
 OUTFILE=webserver6-$(WEBDIR)-$(TARGET)
endif

ifndef MCU
#TODO:extract MCU from platform
  MCU=atmega1284p
endif

all:
	${MAKE} -f Makefile.webserver TARGET=$(TARGET) MIB_INIT=mib-init-raven.c NOAVRSIZE=1 webserver6.elf   
	@if [ $(OUTFILE) != "webserver6" ]; then cp webserver6.elf $(OUTFILE).elf;fi
	avr-objcopy -O ihex -R .eeprom -R .fuse -R .signature $(OUTFILE).elf $(OUTFILE).hex
	avr-size -C --mcu=$(MCU) $(OUTFILE).elf

clean:
	${MAKE} -f Makefile.webserver TARGET=$(TARGET) clean
	rm symbols.c symbols.h webserver6.elf $(OUTFILE).elf  $(OUTFILE).hex
	rm -rf obj_avr-raven

upload:
	@echo "Programming extended fuse..."
	sudo avrdude -c jtag2 -P usb -p $(MCU) -U efuse:w:0xFF:m
	@echo "Waiting for mote to become available again..."
	@sleep 5s
	@echo "Programming low fuse..."
	sudo avrdude -c jtag2 -P usb -p $(MCU) -U lfuse:w:0xE2:m
	@echo "Waiting for mote to become available again..."
	@sleep 5s
	@echo "Programming high fuse..."
	sudo avrdude -c jtag2 -P usb -p $(MCU) -U hfuse:w:0x99:m
	@echo "Waiting for mote to become available again..."
	@sleep 5s
	@echo "Programming flash memory..."
	sudo avrdude -c jtag2 -P usb -p $(MCU) -U flash:w:$(OUTFILE).hex
	@echo "Waiting for mote to become available again..."
	@sleep 5s
	@echo "Programming MAC address..."
	sudo avrdude -c jtag2 -P usb -p $(MCU) -U eeprom:w:mote.eep
