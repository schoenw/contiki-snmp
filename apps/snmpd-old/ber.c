/* -----------------------------------------------------------------------------
 * SNMP implementation for Contiki
 *
 * Copyright (C) 2010 Siarhei Kuryla
 *
 * This program is part of free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
#include <string.h>
#include <stdlib.h>

#include "snmpd-conf.h"
#include "ber.h"
#include "logging.h"
#include "utils.h"


#define CHECK_PTR_MA(ptr) if (!ptr) { snmp_log("can not allocate memory, line: %d\n", __LINE__); return ERR_MEMORY_ALLOCATION; }

/** \brief ber encoded value. */
typedef struct {
    /** \brief buffer. */
    u8t* buffer;
    /** \brief length of the buffer. */
    u8t len;
} ber_value_t;

/** NULL value of the variable binding. */
static const ber_value_t ber_void_null = {(u8t*)"\x05\x00", 2};

#if SNMP_VERSION_3
static const ber_value_t ber_no_such_object = {(u8t*)"\x80\x00", 2};

static const ber_value_t ber_no_such_instance = {(u8t*)"\x81\x00", 2};

static const ber_value_t ber_end_of_mib = {(u8t*)"\x82\x00", 2};
#endif

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded SNMP message.
 */
s8t ber_decode_type(const u8t* const input, const u16t len, u16t* pos, u8t* type)
{
    if (*pos < len) {
        switch (input[*pos]) {
            case BER_TYPE_BOOLEAN:
            case BER_TYPE_INTEGER:
            case BER_TYPE_BIT_STRING:
            case BER_TYPE_OCTET_STRING:
            case BER_TYPE_NULL:
            case BER_TYPE_OID:
            case BER_TYPE_SEQUENCE:
            case BER_TYPE_IPADDRESS:
            case BER_TYPE_COUNTER:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_OPAQUE:
            case BER_TYPE_GAUGE:
            case BER_TYPE_SNMP_GET:
            case BER_TYPE_SNMP_GETNEXT:
            case BER_TYPE_SNMP_RESPONSE:
            case BER_TYPE_SNMP_SET:
            case BER_TYPE_SNMP_GETBULK:
            case BER_TYPE_SNMP_INFORM:
            case BER_TYPE_SNMP_TRAP:
                *type = input[*pos];
                *pos = *pos + 1;
                break;
            default:
                snmp_log("unsupported BER type %02X\n", input[*pos]);
                return -1;
        }
    } else {
        snmp_log("unexpected end of the SNMP request (pos=%d, len=%d) [1]\n", *pos, len);
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded length field.
 */
s8t ber_decode_length(const u8t* const input, const u16t len, u16t* pos, u16t* length)
{
    if (*pos < len) {
        /* length is encoded in a single length byte */
        if (!(input[*pos] & 0x80)) {
            *length = input[*pos];
            *pos = *pos + 1;
        } else {
            /* constructed, definite-length method or indefinite-length method is used */
            u8t size_of_length = input[*pos] & 0x7F;
            *pos = *pos + 1;
            /* the length only up to 2 octets is supported*/
            if (size_of_length > 2) {
                snmp_log("unsupported value of the length field occurs (must be up to 2 bytes)");
                return 1;
            }
            *length = 0;
            while (size_of_length--) {
                if (*pos < len) {
                    *length = (*length << 8) + input[*pos];
                    *pos = *pos + 1;
                } else {
                    snmp_log("can't fetch length, unexpected end of the SNMP request [2]\n");
                    return -1;
                }
            }
        }
    } else {
        snmp_log("can't fetch length, unexpected end of the SNMP request [3]\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode BER encoded type and length fields.
 */
s8t ber_decode_type_length(const u8t* const input, const u16t len, u16t* pos, u8t* type, u16t* length)
{
    if (ber_decode_type(input, len, pos, type) == -1 || !ber_decode_length(input, len, pos, length) == -1) {
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode BER encoded sequence header.
 */
s8t ber_decode_sequence(const u8t* const input, const u16t len, u16t* pos)
{
    u8t type;
    u16t length;
    TRY(ber_decode_type_length(input, len, pos, &type, &length));
    if (type != BER_TYPE_SEQUENCE || length != (len - *pos)) {
        snmp_log("bad type or length value for an expected sequence: type %02X length %d\n", type, length);
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode BER encoded sequence header.
 */
s8t ber_decode_sequence_length(const u8t* const input, const u16t len, u16t* pos, u16t* length)
{
    u8t type;
    TRY(ber_decode_type_length(input, len, pos, &type, length));
    if (type != BER_TYPE_SEQUENCE) {
        snmp_log("bad type for an expected sequence: type %02X length %d\n", type, length);
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded integer value.
 */
s8t ber_decode_integer(const u8t* const input, const u16t len, u16t* pos, s32t* value)
{
    u8t type;
    u16t length;
    /* type and length */
    TRY(ber_decode_type_length(input, len, pos, &type, &length));
    if (type != BER_TYPE_INTEGER || length < 1) {
        snmp_log("bad type or length value for an expected integer: type %02X length %d\n", type, length);
        return -1;
    }

    /* value */
    if (*pos + length - 1 < len) {
        memset(value, (input[*pos] & 0x80) ? 0xFF : 0x00, sizeof (*value));
        while ((length)--) {
            *value = (*value << 8) + input[*pos];
            *pos = *pos + 1;
        }
    } else {
        snmp_log("can't fetch an integer: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded integer value.
 */
s8t ber_decode_unsigned_integer(const u8t* const input, const u16t len, u16t* pos, u32t* value)
{
    u8t type;
    u16t length;
    /* type and length */
    TRY(ber_decode_type_length(input, len, pos, &type, &length));
    if (type != BER_TYPE_GAUGE || length < 1) {
        snmp_log("bad type or length value for an expected integer: type %02X length %d\n", type, length);
        return -1;
    }

    /* type */
    if (*pos + length - 1 < len) {
        *value = 0;
        while (length--) {
            *value = (*value << 8) | input[*pos];
            *pos = *pos + 1;
        }
    } else {
        snmp_log("can't fetch an unsigned integer: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded unsigned integer value.
 */
s8t ber_decode_string(u8t* const input, const u16t len, u16t* pos, u8t** value, u16t* field_len)
{
    u8t type;
    TRY(ber_decode_type_length(input, len, pos, &type, field_len));
    if (type != BER_TYPE_OCTET_STRING) {
        snmp_log("SNMP string must be of type %02X, byt not %02X\n", BER_TYPE_OCTET_STRING, type);
        return -1;
    }
    if (*pos + *field_len - 1 < len) {
        *value = &input[*pos];
        *pos = *pos + *field_len;
    } else {
        snmp_log("can't fetch an octet string: unexpected end of the SNMP input\n");
        return -1;
    }
    return 0;
}

u8t ber_decode_oid_item(u8t* ptr, u8t len, u32t* value)
{
    u8t i = 0;
    *value = 0;
    while (i < len) {
        *value = (*value << 7) + (ptr[i] & 0x7F);
        i++;
        if (!(ptr[i] & 0x80)) {
            break;
        }
    }
    return i;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded OID.
 */
s8t ber_decode_oid(u8t* const input, const u16t len, u16t* pos, ptr_t* o)
{
    u8t type;
    u16t length;
    TRY(ber_decode_type_length(input, len, pos, &type, &length));
    if (type != BER_TYPE_OID || length < 1) {
        snmp_log("bad type or length of the OID: type %02X length %d\n", type, length);
        return -1;
    }

    if (*pos + length <= len) {
        o->len = length;
        o->ptr = &input[*pos];
        *pos += length;
    } else {
        snmp_log("can't fetch an oid: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded void value.
 */
s8t ber_decode_void(const u8t* const input, const u16t len, u16t* pos)
{
    u8t type;
    u16t length;
    TRY(ber_decode_type_length(input, len, pos, &type, &length));
    if ((type == BER_TYPE_NULL && length != 0) || (type != BER_TYPE_NULL && length == 0)) {
        snmp_log("bad type of length of a void value: type %02X length %d\n", type, length);
        return -1;
    }
    if (*pos + length - 1 < len) {
        *pos = *pos + length;
    } else {
        snmp_log("can't fetch void: unexpected end of the SNMP request\n");
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Decode a BER encoded value.
 */
s8t ber_decode_value(u8t* const input, const u16t len, u16t* pos, u8t* value_type, varbind_value_t* value)
{
    if (*pos < len) {
        *value_type = input[*pos];
        switch (input[*pos]) {
            case BER_TYPE_INTEGER:
                TRY(ber_decode_integer(input, len, pos, &value->i_value));
                break;
            case BER_TYPE_IPADDRESS:
            case BER_TYPE_OCTET_STRING:
                TRY(ber_decode_string(input, len, pos, &(value->p_value.ptr), &(value->p_value.len)));
                break;
            case BER_TYPE_NULL:
                TRY(ber_decode_void(input, len, pos));
                break;
            case BER_TYPE_GAUGE:
            case BER_TYPE_TIME_TICKS:
            case BER_TYPE_COUNTER:
                TRY(ber_decode_unsigned_integer(input, len, pos, &value->u_value));
                break;
            case BER_TYPE_OPAQUE:
            case BER_TYPE_OID:
                TRY(ber_decode_oid(input, len, pos, (ptr_t*)&value->p_value));
                break;
            default:
                snmp_log("unsupported BER type %02X\n", input[*pos]);
                return -1;
        }
    } else {
        snmp_log("unexpected end of the SNMP request (pos=%d, len=%d) [1]\n", *pos, len);
        return -1;
    }
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Parse a BER encoded SNMP request.
 */
s8t ber_decode_pdu(u8t* const input, const u16t len, u16t* pos, pdu_t* pdu)
{
    /* request PDU */
    u16t length;
    s32t tmp;

    /* pdu type */
    TRY(ber_decode_type_length(input, len, pos, &pdu->request_type, &length));
    if (length != (len - *pos)) {
        snmp_log("the length of the PDU should be %d, got %d\n", (len - *pos), length);
        return -1;
    }
    snmp_log("request type: %d\n", pdu->request_type);

    /* request-id */
    TRY(ber_decode_integer(input, len, pos, &pdu->request_id));
    snmp_log("request id: %d\n", pdu->request_id);

    /* error-state */
    TRY(ber_decode_integer(input, len, pos, &tmp));
    pdu->error_status = (u8t)tmp;
    snmp_log("error-status: %d\n", pdu->error_status);

    /* error-index */
    TRY(ber_decode_integer(input, len, pos, &tmp));
    pdu->error_index = (u8t)tmp;
    snmp_log("error-index: %d\n", pdu->error_index);

    /* variable-bindings */
    pdu->varbind_index = *pos;
    snmp_log("varbind index %d\n", *pos);
    TRY(ber_decode_sequence(input, len, pos));

    /* variable binding list */
    pdu->varbind_first_ptr = 0;
    varbind_list_item_t* cur_ptr = 0;
    while (*pos < len) {
        /* sequence */
        TRY(ber_decode_sequence_length(input, len, pos, &length));

        if (!pdu->varbind_first_ptr) {
            cur_ptr = pdu->varbind_first_ptr = varbind_list_append(0);
        } else {
            cur_ptr = varbind_list_append(cur_ptr);
        }
        if (!cur_ptr) {
            return ERR_MEMORY_ALLOCATION;
        }

        /* OID */
        cur_ptr->varbind.oid_ptr = oid_create();
        TRY(ber_decode_oid(input, len, pos, cur_ptr->varbind.oid_ptr));

        /* void value */
        TRY(ber_decode_value(input, len, pos, &cur_ptr->varbind.value_type, &cur_ptr->varbind.value));
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded length to the buffer
 */
s8t ber_encode_length(u8t* output, s16t* pos, u16t length)
{
    if (length > 0xFF) {
        DECN(pos, 3);
        /* first "the length of the length" goes in octets */
        /* the bit 0x80 of the first byte is set to show that the length is composed of multiple octets */
        output[*pos] = 0x82;
        output[*pos + 1] = (length >> 8) & 0xFF;
        output[*pos + 2] = length & 0xFF;
    } else if (length > 0x7F) {
        DECN(pos, 2);
        output[*pos] = 0x81;
	output[*pos + 1] = length & 0xFF;
    } else {
        DEC(pos);
        output[*pos] = length & 0x7F;
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded variable binding to the buffer
 */
s8t ber_encode_type_length(u8t* output, s16t* pos, u8t type, u16t len)
{
    TRY(ber_encode_length(output, pos, len));
    DEC(pos);
    output[*pos] = type;
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Get the length of the oid item in BER encoding.
 */
u8t ber_encoded_oid_item_length(u32t value) {
    if (value >= (268435456)) { // 2 ^ 28
        return 5;
    } else if (value >= (2097152)) { // 2 ^ 21
        return 4;
    } else if (value >= 16384) { // 2 ^ 14
        return 3;
    } else if (value >= 128) { // 2 ^ 7
        return 2;
    } else {
        return 1;
    }
}

/*-----------------------------------------------------------------------------------*/
/*
 * Return a BER encoded value.
 */
s8t ber_encode_oid_item(u32t value, u8t* ptr) {
    u8t length = ber_encoded_oid_item_length(value);
    ptr[0] = 1;
    s8t j = 0;
    for (j = length - 1; j >= 0; j--) {
        if (j) {
            ptr[length - j - 1] = ((value >> (7 * j)) & 0x7F) | 0x80;
        } else {
            ptr[length - j - 1] = ((value >> (7 * j)) & 0x7F);
        }
    }
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded oid to the buffer
 */
s8t ber_encode_oid(u8t* output, s16t* pos, u8t* ptr, u16t len)
{
    DECN(pos, len);
    memcpy(&output[*pos], ptr, len);
    /* type and length */
    TRY(ber_encode_type_length(output, pos, BER_TYPE_OID, len));
    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded integer to the buffer
 */
s8t ber_encode_integer(u8t* output, s16t* pos, u8t type, const s32t value)
{
    s16t init_pos = *pos;
    u16t length;
    s8t j;

    /* get the length of the BER encoded integer value in bytes */
    if (value < -16777216 || value > 16777215) {
        length = 4;
    } else if (value < -32768 || value > 32767) {
        length = 3;
    } else if (value < -128 || value > 127) {
        length = 2;
    } else {
        length = 1;
    }

    /* write integer value */
    DECN(pos, length);
    for (j = length - 1; j >= 0; j--) {
        output[*pos + (length - 1) - j] = (((u32t)value) >> (8 * j)) & 0xFF;
    }

    /* write type and length */
    TRY(ber_encode_type_length(output, pos, type, init_pos - *pos));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded unsigned integer to the buffer
 */
s8t ber_encode_unsigned_integer(u8t* output, s16t* pos, const u8t type, const u32t value)
{
    s16t init_pos = *pos;
    u16t length;
    s8t j;

    /* get the length of the BER encoded integer value in bytes */
    if (value & 0xFF000000) {
        length = 4;
    } else if (value & 0x00FF0000) {
        length = 3;
    } else if (value & 0x0000FF00) {
        length = 2;
    } else {
        length = 1;
    }

    /* write integer value */
    DECN(pos, length);
    for (j = length - 1; j >= 0; j--) {
        output[*pos + (length - 1) - j] = (value >> (8 * j)) & 0xFF;
    }

    /* write type and length */
    TRY(ber_encode_type_length(output, pos, type, init_pos - *pos));

    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded string value to the buffer
 */
s8t ber_encode_fixed_string(u8t* output, s16t* pos, const u8t* const str_value, const u16t len)
{
    /* string value */
    DECN(pos, len);
    memcpy(output + *pos, str_value, len);

    /* type and length */
    TRY(ber_encode_type_length(output, pos, BER_TYPE_OCTET_STRING, len));

    return 0;
}


/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded string value to the buffer
 */
s8t ber_encode_string(u8t* output, s16t* pos, const u8t* const str_value)
{
    return ber_encode_fixed_string(output, pos, str_value, strlen((char*)str_value));
}

/*-----------------------------------------------------------------------------------*/
/*
 * Write a BER encoded variable binding to the buffer
 */
s8t ber_encode_var_bind(u8t* output, s16t* pos, const varbind_t* const varbind)
{
    /* write the variable binding in the reverse order */
    u16t len_pos = *pos;
    /* value */
    switch (varbind->value_type) {
        case BER_TYPE_OCTET_STRING:
            TRY(ber_encode_fixed_string(output, pos, varbind->value.p_value.ptr, varbind->value.p_value.len));
            break;

        case BER_TYPE_INTEGER:
        case BER_TYPE_COUNTER:
        case BER_TYPE_GAUGE:
        case BER_TYPE_TIME_TICKS:
            TRY(ber_encode_integer(output, pos, varbind->value_type, varbind->value.i_value));
            break;

        case BER_TYPE_NULL:
            DECN(pos, ber_void_null.len);
            memcpy(output + (*pos), ber_void_null.buffer, ber_void_null.len);
            break;

        case BER_TYPE_OID:
            TRY(ber_encode_oid(output, pos, varbind->value.p_value.ptr, varbind->value.p_value.len));
            break;

#if SNMP_VERSION_3
        case BER_TYPE_NO_SUCH_OBJECT:
            DECN(pos, ber_no_such_object.len);
            memcpy(output + (*pos), ber_no_such_object.buffer, ber_no_such_object.len);
            break;

        case BER_TYPE_NO_SUCH_INSTANCE:
            DECN(pos, ber_no_such_instance.len);
            memcpy(output + (*pos), ber_no_such_instance.buffer, ber_no_such_instance.len);
            break;

        case BER_TYPE_END_OF_MIB:
            DECN(pos, ber_end_of_mib.len);
            memcpy(output + (*pos), ber_end_of_mib.buffer, ber_end_of_mib.len);
            break;
#endif
        default:
            break;
    }
    /* oid */
    TRY(ber_encode_oid(output, pos, varbind->oid_ptr->ptr, varbind->oid_ptr->len));

    /* sequence header*/
    TRY(ber_encode_type_length(output, pos, BER_TYPE_SEQUENCE, len_pos - *pos));
    return 0;
}

/*-----------------------------------------------------------------------------------*/
/*
 * Encode SNMP PDU
 */
s8t ber_encode_pdu(u8t* output, s16t* pos, const u8t* const input, u16t input_len, const pdu_t* const  pdu, const u16t max_output_len)
{
    /* write in the reverse order */
    if (pdu->error_status == ERROR_STATUS_NO_ERROR) {
	/* 
	 * the code below (double while) looks inefficient but for short lists
	 * it is unbeatable because it doesn't require extra memory
	 * and it keeps the list unmodified
	 *
	 */
	
        varbind_list_item_t* ptrLast = NULL;

        while (ptrLast != pdu->varbind_first_ptr) {
	  /* variable binding list */	
	  varbind_list_item_t* ptr = pdu->varbind_first_ptr;
	  
	  while (ptr && ptr->next_ptr != ptrLast) {
	    ptr = ptr->next_ptr;
	  }	 
	  TRY(ber_encode_var_bind(output, pos, &ptr->varbind));
	  ptrLast = ptr;
        }
        TRY(ber_encode_type_length(output, pos, BER_TYPE_SEQUENCE, max_output_len - *pos));
    } else {
        DECN(pos, (input_len - pdu->varbind_index));
        memcpy(&output[*pos], &input[pdu->varbind_index], input_len - pdu->varbind_index);
    }

    /* error index */
    TRY(ber_encode_integer(output, pos, BER_TYPE_INTEGER, pdu->error_index));
    /* error status */
    TRY(ber_encode_integer(output, pos, BER_TYPE_INTEGER, pdu->error_status));
    /* request id */
    TRY(ber_encode_integer(output, pos, BER_TYPE_INTEGER, pdu->request_id));

    /* sequence header*/
    TRY(ber_encode_type_length(output, pos, pdu->response_type, max_output_len - *pos));

    return 0;
}
