#include <stdlib.h>

#include "mib-init.h"
#include "ber.h"
#include "utils.h"
#include "logging.h"

#if CONTIKI_TARGET_AVR_RAVEN && ENABLE_PROGMEM
#include <avr/pgmspace.h>
#else
#define PROGMEM
#endif

/* common oid prefixes*/
static u8t ber_oid_system_desc[] PROGMEM  = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00};
static ptr_t oid_system_desc PROGMEM      = {ber_oid_system_desc, 8};
static u8t ber_oid_system_time[] PROGMEM  = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00};
static ptr_t oid_system_time PROGMEM      = {ber_oid_system_time, 8};
static u8t ber_oid_system_str[] PROGMEM   = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x0B, 0x00};
static ptr_t oid_system_str PROGMEM       = {ber_oid_system_str, 8};
static u8t ber_oid_system_tick[] PROGMEM  = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x0D, 0x00};
static ptr_t oid_system_tick PROGMEM      = {ber_oid_system_tick, 8};

static u8t ber_oid_if_number[] PROGMEM    = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x01, 0x00};
static ptr_t oid_if_number PROGMEM        = {ber_oid_if_number, 8};

static u8t ber_oid_if_table[] PROGMEM     = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01};
static ptr_t oid_if_table PROGMEM         = {ber_oid_if_table, 8};

static u8t ber_oid_test_int[] PROGMEM     = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x89, 0x52, 0x01, 0x00};
static ptr_t oid_test_int PROGMEM         = {ber_oid_test_int, 9};
static u8t ber_oid_test_uint[] PROGMEM    = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x89, 0x52, 0x02, 0x00};
static ptr_t oid_test_uint PROGMEM        = {ber_oid_test_uint, 9};


s8t getSysDescr(mib_object_t* object, u8t* oid, u8t len)
{
    if (!object->varbind.value.p_value.len) {
        object->varbind.value.p_value.ptr = (u8t*)"System Description";
        object->varbind.value.p_value.len = 18;
    }
    return 0;
}

s8t setSysDescr(mib_object_t* object, u8t* oid, u8t len, varbind_value_t value)
{
    object->varbind.value.p_value.ptr = (u8t*)"System Description2";
    object->varbind.value.p_value.len = 19;
    return 0;
}

s8t getTimeTicks(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.u_value = 1234;
    return 0;
}

/**** IF-MIB ****************/

#define ifNumber 3

s8t getIfNumber(mib_object_t* object, u8t* oid, u8t len)
{
    object->varbind.value.i_value = ifNumber;
    return 0;
}

#define ifIndex 1

s8t getIf(mib_object_t* object, u8t* oid, u8t len)
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
            if (0 < oid_el2 && oid_el2 <= ifNumber) {
                object->varbind.value.i_value = oid_el2;
            } else {
                return -1;
            }
            break;
        default:
            break;
    }
    return 0;
}

ptr_t* getNextIfOid(mib_object_t* object, u8t* oid, u8t len)
{
    u32t oid_el1, oid_el2;
    u8t i;
    i = ber_decode_oid_item(oid, len, &oid_el1);
    i = ber_decode_oid_item(oid + i, len - i, &oid_el2);

    if (oid_el1 < ifIndex || (oid_el1 == ifIndex && oid_el2 < ifNumber)) {
        ptr_t* ret = oid_create();
        CHECK_PTR_U(ret);
        ret->len = 2;
        ret->ptr = malloc(2);
        CHECK_PTR_U(ret->ptr);
        ret->ptr[0] = ifIndex;
        if (oid_el1 < ifIndex) {
            ret->ptr[1] = 1;
        } else {
            ret->ptr[1] = oid_el2 + 1;
        }
        return ret;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Initialize the MIB.
 */
s8t mib_init()
{
    const u32t tconst = 12345678;
    if (add_scalar(&oid_system_desc, 0, BER_TYPE_OCTET_STRING, 0, &getSysDescr, &setSysDescr) == -1 ||
        add_scalar(&oid_system_time, 0, BER_TYPE_TIME_TICKS, 0, &getTimeTicks, 0) == -1  ||
        add_scalar(&oid_system_str, 0, BER_TYPE_OCTET_STRING, "Pointer to a string", 0, 0) == -1 ||
        add_scalar(&oid_system_tick, 0, BER_TYPE_TIME_TICKS, &tconst, 0, 0) == -1) {
        return -1;
    }
    if (add_scalar(&oid_if_number, 0, BER_TYPE_INTEGER, 0, &getIfNumber, 0) == -1) {
        return -1;
    }

    if (add_table(&oid_if_table, &getIf, &getNextIfOid, 0) == -1) {
        return -1;
    }

    if (add_scalar(&oid_test_int, 0, BER_TYPE_INTEGER, 0, 0, 0) == -1 ||
       add_scalar(&oid_test_uint, 0, BER_TYPE_GAUGE, 0, 0, 0) == -1) {
        return -1;
    }
    return 0;
}