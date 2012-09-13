#include <stdlib.h>
#include <string.h>

#include "contiki.h"

#include "mib-init-raven.h"
#include "mib-init.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"
#include "dispatcher.h"
#include "snmpd.h"
#include "sysman.h"
#if CONTIKI_TARGET_AVR_RAVEN && ENABLE_PROGMEM
#include "rf230bb.h"
#include "raven-lcd.h"
#include <avr/pgmspace.h>
#else
#define PROGMEM
#endif

#define AVR_SNMP 1

/* SNMPv2 system group */
static u8t ber_oid_system_sysDesc[] PROGMEM             = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
static ptr_t oid_system_sysDesc PROGMEM                 = {ber_oid_system_sysDesc, 8};
static u8t ber_oid_system_sysObjectId [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00};
static ptr_t oid_system_sysObjectId PROGMEM             = {ber_oid_system_sysObjectId, 8};
static u8t ber_oid_system_sysUpTime [] PROGMEM          = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00};
static ptr_t oid_system_sysUpTime PROGMEM               = {ber_oid_system_sysUpTime, 8};
static u8t ber_oid_system_sysContact [] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00};
static ptr_t oid_system_sysContact PROGMEM              = {ber_oid_system_sysContact, 8};
static u8t ber_oid_system_sysName [] PROGMEM            = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00};
static ptr_t oid_system_sysName PROGMEM                 = {ber_oid_system_sysName, 8};
static u8t ber_oid_system_sysLocation [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00};
static ptr_t oid_system_sysLocation PROGMEM             = {ber_oid_system_sysLocation, 8};
static u8t ber_oid_system_sysServices [] PROGMEM        = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07, 0x00};
static ptr_t oid_system_sysServices PROGMEM             = {ber_oid_system_sysServices, 8};
static u8t ber_oid_system_sysORLastChange [] PROGMEM    = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x08, 0x00};
static ptr_t oid_system_sysORLastChange PROGMEM         = {ber_oid_system_sysORLastChange, 8};
static u8t ber_oid_system_sysOREntry [] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x09, 0x01};
static ptr_t oid_system_sysOREntry PROGMEM              = {ber_oid_system_sysOREntry, 8};

/* interfaces group*/
static u8t ber_oid_ifNumber[] PROGMEM                   = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x01, 0x00};
static ptr_t oid_ifNumber PROGMEM                       = {ber_oid_ifNumber, 8};
static u8t ber_oid_ifEntry[] PROGMEM                    = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01};
static ptr_t oid_ifEntry PROGMEM                        = {ber_oid_ifEntry, 8};

/* SNMP group */
static u8t ber_oid_snmpInPkts[] PROGMEM                 = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x01, 0x00};
static ptr_t oid_snmpInPkts PROGMEM                     = {ber_oid_snmpInPkts, 8};
static u8t ber_oid_snmpInBadVersions[] PROGMEM          = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x03, 0x00};
static ptr_t oid_snmpInBadVersions PROGMEM              = {ber_oid_snmpInBadVersions, 8};
static u8t ber_oid_snmpInASNParseErrs[] PROGMEM         = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x06, 0x00};
static ptr_t oid_snmpInASNParseErrs PROGMEM             = {ber_oid_snmpInASNParseErrs, 8};
static u8t ber_oid_snmpEnableAuthenTraps[] PROGMEM      = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x1E, 0x00};
static ptr_t oid_snmpEnableAuthenTraps PROGMEM          = {ber_oid_snmpEnableAuthenTraps, 8};
static u8t ber_oid_snmpSilentDrops[] PROGMEM            = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x1F, 0x00};
static ptr_t oid_snmpSilentDrops PROGMEM                = {ber_oid_snmpSilentDrops, 8};
static u8t ber_oid_snmpProxyDrops[] PROGMEM             = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x0B, 0x20, 0x00};
static ptr_t oid_snmpProxyDrops PROGMEM                 = {ber_oid_snmpProxyDrops, 8};

/* ifXTable */
static u8t ber_oid_ifXEntry[] PROGMEM                   = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x1f, 0x01, 0x01, 0x01};
static ptr_t oid_ifXEntry PROGMEM                       = {ber_oid_ifXEntry, 9};

/* entPhySensorEntry */
static u8t ber_oid_entPhySensorEntry[] PROGMEM          = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x63, 0x01, 0x01, 0x01};
static ptr_t oid_entPhySensorEntry PROGMEM              = {ber_oid_entPhySensorEntry, 9};

/* SNMPv2 snmpSet group */
static u8t ber_oid_snmpSetSerialNo[] PROGMEM            = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x01, 0x01, 0x06, 0x01, 0x00};
static ptr_t oid_snmpSetSerialNo PROGMEM                = {ber_oid_snmpSetSerialNo, 10};

ptr_t* handleTableNextOid2(u8t* oid, u8t len, u8t* columns, u8t columnNumber, u8t rowNumber) {
    ptr_t* ret = 0;
    u32t oid_el1, oid_el2;
    u8t i;
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i = ber_decode_oid_item(oid + i, len - i, &oid_el2);
    for (i = 0; i < columnNumber; i++) {
        if (oid_el1 < columns[i] || (oid_el1 == columns[i] && oid_el2 < rowNumber)) {
            ret = oid_create();
            CHECK_PTR_U(ret);
            ret->len = 2;
            ret->ptr = malloc(2);
            CHECK_PTR_U(ret->ptr);
            ret->ptr[0] = columns[i];
            if (oid_el1 < columns[i]) {
                ret->ptr[1] = 1;
            } else {
                ret->ptr[1] = oid_el2 + 1;
            }
            break;
        }
    }
    return ret;
}

/*
 *  "system" group
 */
s8t getTimeTicks(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = getSysUpTime();
    return 0;
}

/* ----------------   sysORTable    -------------------------- */

#define sysORID         2
#define sysORDescr      3
#define sysORUpTime     4

u8t sysORTableColumns[] = {sysORID, sysORDescr, sysORUpTime};

#define ORTableSize     1

static u8t ber_oid_mib2[]              = {0x2b, 0x06, 0x01, 0x06, 0x03, 0x01};
static ptr_t oid_mib2                  = {ber_oid_mib2, 6};

static u8t ber_oid_jacobs_raven[]      = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xf2, 0x06, 0x01, 0x01};
static ptr_t oid_jacobs_raven          = {ber_oid_jacobs_raven, 10};

s8t getOREntry(mib_object_t* object, u8t* oid, u8t len)
{
    u32t oid_el1, oid_el2;
    u8t i;
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

    if (len != 2) {
        return -1;
    }

    switch (oid_el1) {
        case sysORID: 
            object->varbind.value_type = BER_TYPE_OID;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.p_value.ptr = oid_mib2.ptr;
                    object->varbind.value.p_value.len = oid_mib2.len;
                    break;
                default:
                    return -1;
            }
            break;
        case sysORDescr:
            object->varbind.value_type = BER_TYPE_OCTET_STRING;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.p_value.ptr = (u8t*)"The MIB module for SNMP entities";
                    object->varbind.value.p_value.len = strlen((char*)object->varbind.value.p_value.ptr);
                    break;
                default:
                    return -1;
            }
            break;
        case sysORUpTime:
            object->varbind.value_type = BER_TYPE_TIME_TICKS;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 0;
                    break;
                default:
                    return -1;
            }
            break;
        default:
            return -1;
    }
    return 0;
}

ptr_t* getNextOREntry(mib_object_t* object, u8t* oid, u8t len)
{
    return handleTableNextOid2(oid, len, sysORTableColumns, 3, ORTableSize);
}

/*
 * interfaces group
 */
#define ifIndex             1
#define ifDescr             2
#define ifType              3
#define ifMtu               4
#define ifSpeed             5
#define ifPhysAddress       6
#define ifAdminStatus       7
#define ifOperStatus        8
#define ifLastChange        9
#define ifInOctets          10
#define ifInUcastPkts       11
#define ifInErrors          14
#define ifInUnknownProtos   15
#define ifOutOctets         16
#define ifOutUcastPkts      17
#define ifOutErrors         20

#if CONTIKI_TARGET_AVR_RAVEN
u8t phyAddress[8];

void getPhyAddress(varbind_value_t* value) {
    radio_get_extended_address(phyAddress);
    value->p_value.ptr = phyAddress;
    value->p_value.len = 8;
}

extern uint8_t rf230_last_rssi;
extern uint16_t RF230_sendpackets,RF230_receivepackets,RF230_sendfail,RF230_receivefail;
//extern uint16_t RF230_sendBroadcastPkts, RF230_receiveBroadcastPkts;
extern uint32_t RF230_sendOctets, RF230_receiveOctets;
#define RF230_sendBroadcastPkts 0
#define RF230_receiveBroadcastPkts 0
#else
#define RF230_sendpackets       0
#define RF230_receivepackets    0
#define RF230_sendBroadcastPkts 0
#define RF230_receiveBroadcastPkts 0
#define RF230_sendOctets 0
#define RF230_receiveOctets 0
#define RF230_sendfail 0
#define RF230_receivefail 0
#endif

s8t getIfEntry(mib_object_t* object, u8t* oid, u8t len)
{
    u32t oid_el1, oid_el2;
    u8t i;
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

    if (len != 2) {
        return -1;
    }

    switch (oid_el1) {
        case ifIndex:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.i_value = 1;
                    break;
                default:
                    return -1;
            }
            break;
        case ifDescr:
            object->varbind.value_type = BER_TYPE_OCTET_STRING;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.p_value.ptr = (u8t*)getIfName();
                    object->varbind.value.p_value.len = strlen(getIfName());
                    break;
                default:
                    return -1;
            }
            break;
        case ifType:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.i_value = 6;
                    break;
                default:
                    return -1;
            }
            break;            
        case ifMtu:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.i_value = 127;
                    break;
                default:
                    return -1;
            }
            break;

        case ifSpeed:
            object->varbind.value_type = BER_TYPE_GAUGE;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 250000;
                    break;
                default:
                    return -1;
            }
            break;

	    
        case ifPhysAddress:
            object->varbind.value_type = BER_TYPE_OCTET_STRING;
            switch (oid_el2) {
                case 1:
                    #if CONTIKI_TARGET_AVR_RAVEN
                    getPhyAddress(&object->varbind.value);
                    #else
                    object->varbind.value.p_value.ptr = (u8t*)"NO-ADDR"; // TODO: put the real address
                    object->varbind.value.p_value.len = 6;
                    #endif
                    break;
                default:
                    return -1;
            }
            break;
	    

        case ifAdminStatus:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 1;
                    break;
                default:
                    return -1;
            }
            break;
        case ifOperStatus:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 1;
                    break;
                default:
                    return -1;
            }
            break;
        case ifLastChange:
            object->varbind.value_type = BER_TYPE_TIME_TICKS;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 0;
                    break;
                default:
                    return -1;
            }
            break;

	    
        case ifInOctets:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = (uint32_t)getReceivedOctets();
                    break;
                default:
                    return -1;
            }
            break;

        case ifInUcastPkts:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = getReceivedPackets() - RF230_receiveBroadcastPkts;
                    break;
                default:
                    return -1;
            }
            break;
	    

        case ifInErrors:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = getFailReceived();
                    break;
                default:
                    return -1;
            }
            break;

        case ifInUnknownProtos:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 0;
                    break;
                default:
                    return -1;
            }
            break;

	    
        case ifOutOctets:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = (uint32_t)getSentOctets();
                    break;
                default:
                    return -1;
            }
            break;
	        
        case ifOutUcastPkts:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = getSentPackets() - RF230_sendBroadcastPkts;
                    break;
                default:
                    return -1;
            }
            break;
	    

        case ifOutErrors:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = getFailSent();
                    break;
                default:
                    return -1;
            }
            break;

        default:
            return -1;
    }
    return 0;
}

u8t ifTableColumns[] = {ifIndex, ifDescr, ifType, ifMtu, ifSpeed, ifPhysAddress, ifAdminStatus, ifOperStatus,
                        ifLastChange, ifInOctets, ifInUcastPkts, ifInErrors, ifInUnknownProtos, ifOutOctets, ifOutUcastPkts, ifOutErrors};

#define ifTableSize     1

ptr_t* getNextIfEntry(mib_object_t* object, u8t* oid, u8t len)
{
    return handleTableNextOid2(oid, len, ifTableColumns, 15, ifTableSize);
}

/*
 * ifXTable group
 */
#define ifName                  1
#define ifInMulticastPkts       2
#define ifInBroadcastPkts       3
#define ifOutMulticastPkts      4
#define ifOutBroadcastPkts      5
#define ifLinkUpDownTrapEnable  14
#define ifHighSpeed             15
#define ifPromiscuousMode       16
#define ifConnectorPresent      17

s8t getIfXEntry(mib_object_t* object, u8t* oid, u8t len)
{
    u32t oid_el1, oid_el2;
    u8t i;
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

    if (len != 2) {
        return -1;
    }

    switch (oid_el1) {
        case ifName:
            object->varbind.value_type = BER_TYPE_OCTET_STRING;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.p_value.ptr = (u8t*)getIfName();
                    object->varbind.value.p_value.len = strlen(getIfName());
                    break;
                default:
                    return -1;
            }
            break;
        case ifInMulticastPkts:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 0;
                    break;
                default:
                    return -1;
            }
            break;

	    
        case ifInBroadcastPkts:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = RF230_receiveBroadcastPkts;
                    break;
                default:
                    return -1;
            }
            break;
	    

        case ifOutMulticastPkts:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 0;
                    break;
                default:
                    return -1;
            }
            break;

        case ifOutBroadcastPkts:
            object->varbind.value_type = BER_TYPE_COUNTER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = RF230_sendBroadcastPkts;
                    break;
                default:
                    return -1;
            }
            break;

        case ifLinkUpDownTrapEnable:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.i_value = 2; // disabled
                    break;
                default:
                    return -1;
            }
            break;
        case ifHighSpeed:
            object->varbind.value_type = BER_TYPE_GAUGE;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 0; // 0 + 50000
                    break;
                default:
                    return -1;
            }
            break;

        case ifPromiscuousMode:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 2; // false
                    break;
                default:
                    return -1;
            }
            break;

        case ifConnectorPresent:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 1; // true : 1; false : 0
                    break;
                default:
                    return -1;
            }
            break;

        default:
            return -1;
    }
    return 0;
}

u8t ifXTableColumns[] = {ifName, ifInMulticastPkts, ifInBroadcastPkts, ifOutMulticastPkts, ifOutBroadcastPkts,
                            ifLinkUpDownTrapEnable, ifHighSpeed, ifPromiscuousMode, ifConnectorPresent};

ptr_t* getNextIfXEntry(mib_object_t* object, u8t* oid, u8t len)
{
    return handleTableNextOid2(oid, len, ifXTableColumns, 9, ifTableSize);
}

/*
 * entPhySensorEntry group
 */
#define entPhySensorType            1
#define entPhySensorScale           2
#define entPhySensorPrecision       3
#define entPhySensorValue           4
#define entPhySensorOperStatus      5
#define entPhySensorUnitsDisplay    6
#define entPhySensorValueTimeStamp  7
#define entPhySensorValueUpdateRate 8

#define entPhySensorTableSize       2

u8t entPhySensorTableColumns[] = {entPhySensorType, entPhySensorScale, entPhySensorPrecision, entPhySensorValue, entPhySensorOperStatus,
                                    entPhySensorUnitsDisplay, entPhySensorValueTimeStamp, entPhySensorValueUpdateRate};

u32t tempLastUpdate;

s8t temperature;

/*
 * A callback function for setting the tempurature. Called from the raven-lcd-interface process.
 */
void snmp_set_temp(char* s)
{
    temperature = 0;
    u8t i = 0;
    while ( i < strlen(s) && s[i] >= '0' && s[i] <= '9') {
        temperature = temperature * 10 + s[i] - '0';
        i++;
    }
    tempLastUpdate = getSysUpTime();
}

s8t getEntPhySensorEntry(mib_object_t* object, u8t* oid, u8t len)
{
    u32t oid_el1, oid_el2;
    u8t i;
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

    if (len != 2) {
        return -1;
    }

    switch (oid_el1) {
        case entPhySensorType:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.i_value = 8; // celsius(8): temperature
                    break;
                case 2:
                    object->varbind.value.i_value = 1; // celsius(8): temperature
                    break;
                default:
                    return -1;
            }
            break;
        case entPhySensorScale:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.i_value = 9; // units	(9)
                    break;
                case 2:
                    object->varbind.value.i_value = 9; // units	(9)
                    break;
                default:
                    return -1;
            }
            break;
        case entPhySensorPrecision:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.i_value = 0;
                    break;
                case 2:
                    object->varbind.value.i_value = 0;
                    break;
                default:
                    return -1;
            }
            break;

        case entPhySensorValue:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
		    temperature = getTemperature("C");
                    object->varbind.value.i_value = temperature;		    
                    break;
                case 2:
		    object->varbind.value.i_value = rf230_last_rssi;
                    break;
                default:
                    return -1;
            }
            break;

        case entPhySensorOperStatus:
            object->varbind.value_type = BER_TYPE_INTEGER;
            switch (oid_el2) {
                case 1:
                    if (temperature==-100) {
                        object->varbind.value.i_value = 2;
                    } else {
                        object->varbind.value.i_value = 1;
                    }
                    break;
                case 2:
		    object->varbind.value.i_value = 1;
                    break;
                default:
                    return -1;
            }
            break;

        case entPhySensorUnitsDisplay:
            object->varbind.value_type = BER_TYPE_OCTET_STRING;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.p_value.ptr = (u8t*)"celsius";
                    object->varbind.value.p_value.len = 7;
                    break;
                case 2:
                    object->varbind.value.p_value.ptr = (u8t*)"dBm";
                    object->varbind.value.p_value.len = 3;
                    break;
                default:
                    return -1;
            }
            break;

        case entPhySensorValueTimeStamp:
            object->varbind.value_type = BER_TYPE_TIME_TICKS;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = getLastTempUpdate();
                    break;
                case 2:
                    object->varbind.value.u_value = getLastTempUpdate();
                    break;
                default:
                    return -1;
            }
            break;

       case entPhySensorValueUpdateRate:
            object->varbind.value_type = BER_TYPE_UNSIGNED32;
            switch (oid_el2) {
                case 1:
                    object->varbind.value.u_value = 0;
                    break;
                case 2:
                    object->varbind.value.u_value = 0;
                    break;
                default:
                    return -1;
            }
            break;


        default:
            return -1;
    }
    return 0;
}

ptr_t* getNextEntPhySensorEntry(mib_object_t* object, u8t* oid, u8t len)
{
    return handleTableNextOid2(oid, len, entPhySensorTableColumns, 8, entPhySensorTableSize);
}

/*
 * snmpSet group
 */
s8t setSnmpSetSerialNo(mib_object_t* object, u8t* oid, u8t len, varbind_value_t value)
{
    if (object->varbind.value.u_value + 1 == value.u_value) {
        object->varbind.value.u_value++;

    } else {
        return ERROR_STATUS_BAD_VALUE;
    }
    return 0;
}

/*
 * SNMP group
 */
s8t getMIBSnmpInPkts(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = getSnmpInPkts();
    return 0;
}

s8t getMIBSnmpInBadVersions(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = getSnmpInBadVersions();
    return 0;
}

s8t getMIBSnmpInASNParseErrs(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = getSnmpInASNParseErrs();
    return 0;
}

s8t getMIBSnmpSilentDrops(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = getSnmpSilentDrops();
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Initialize the MIB.
 */
s8t mib_init()
{
    s32t defaultServiceValue = 78;
    s32t defaultSnmpEnableAuthenTraps = 2;
    s32t ifNumber = 1;
    char* sysDesc = getSysDesc();
    char* sysContact = getSysContact();
    char* sysName = getSysName();
    char* sysLocation = getSysLocation();
    

    // system group
    if (add_scalar(&oid_system_sysDesc, FLAG_ACCESS_READONLY, BER_TYPE_OCTET_STRING, sysDesc, 0, 0) == -1 ||
        add_scalar(&oid_system_sysObjectId, FLAG_ACCESS_READONLY, BER_TYPE_OID, &oid_jacobs_raven, 0, 0) == -1 ||
        add_scalar(&oid_system_sysUpTime, FLAG_ACCESS_READONLY, BER_TYPE_TIME_TICKS, 0, &getTimeTicks, 0) == -1 ||
        add_scalar(&oid_system_sysContact, 0, BER_TYPE_OCTET_STRING, sysContact, 0, 0) == -1 ||
        add_scalar(&oid_system_sysName, 0, BER_TYPE_OCTET_STRING, sysName, 0, 0) == -1 ||
        add_scalar(&oid_system_sysLocation, 0, BER_TYPE_OCTET_STRING, sysLocation, 0, 0) == -1 ||
        add_scalar(&oid_system_sysServices, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, &defaultServiceValue, 0, 0) == -1 ||
        add_scalar(&oid_system_sysORLastChange, FLAG_ACCESS_READONLY, BER_TYPE_TIME_TICKS, 0, 0, 0) == -1) {
        return -1;
    }
    if (add_table(&oid_system_sysOREntry, &getOREntry, &getNextOREntry, 0) == -1) {
        return -1;
    }

    // interfaces
    if (add_scalar(&oid_ifNumber, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, &ifNumber, 0, 0) != ERR_NO_ERROR) {
        return -1;
    }
    if (add_table(&oid_ifEntry, &getIfEntry, &getNextIfEntry, 0) == -1) {
        return -1;
    }


    // snmp group
    if (add_scalar(&oid_snmpInPkts, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0, &getMIBSnmpInPkts, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpInBadVersions, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0, &getMIBSnmpInBadVersions, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpInASNParseErrs, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0, &getMIBSnmpInASNParseErrs, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpEnableAuthenTraps, FLAG_ACCESS_READONLY, BER_TYPE_INTEGER, &defaultSnmpEnableAuthenTraps, 0, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpSilentDrops, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0,  &getMIBSnmpSilentDrops, 0) != ERR_NO_ERROR ||
        add_scalar(&oid_snmpProxyDrops, FLAG_ACCESS_READONLY, BER_TYPE_COUNTER, 0,  0, 0) != ERR_NO_ERROR) {
        return -1;
    }

    // ifXTable
    if (add_table(&oid_ifXEntry, &getIfXEntry, &getNextIfXEntry, 0) == -1) {
        return -1;
    }

    // entPhySensorEntry
    if (add_table(&oid_entPhySensorEntry, &getEntPhySensorEntry, &getNextEntPhySensorEntry, 0) == -1) {
        return -1;
    }
    
    // snmpSet group
    if (add_scalar(&oid_snmpSetSerialNo, 0, BER_TYPE_INTEGER, 0, 0, &setSnmpSetSerialNo) != ERR_NO_ERROR) {
        return -1;
    }

    return 0;
}
