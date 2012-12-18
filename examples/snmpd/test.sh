#!/bin/bash

while :
do
    ping6 -c 1 mote1 | grep 'time=' | awk -F'=' '{ print $4}' | awk -F' ' '{ print "0:"$1}'
    snmpwalk -v 1 -c public udp6:mote1:1610 ENTITY-SENSOR-MIB::entPhySensorValue.1 | awk -F': ' '{ print "1:"$2}'
    snmpwalk -v 1 -c public udp6:mote1:1610 ENTITY-SENSOR-MIB::entPhySensorValue.2 | awk -F': ' '{ print "2:"$2}'
#    sleep 0.1
done
