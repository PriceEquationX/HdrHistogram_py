/**

Python C extensions for HdrHistogram python.
These functions are needed to accelerate the encoding and decoding of
the HdrHistogram V2 format which is based on the ZigZag LEB128 format.
The pure python version of these function is too slow.

Written by Alec Hothan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "python-codec.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

static int zig_zag_encode_i64(uint8_t* buffer, int64_t signed_value) {
    int64_t value = signed_value;

    value = (value << 1) ^ (value >> 63);
    int bytesWritten = 0;
    if (value >> 7 == 0) {
        buffer[0] = (uint8_t) value;
        bytesWritten = 1;
    }
    else {
        buffer[0] = (uint8_t) ((value & 0x7F) | 0x80);
        if (value >> 14 == 0) {
            buffer[1] = (uint8_t) (value >> 7);
            bytesWritten = 2;
        } else {
            buffer[1] = (uint8_t) ((value >> 7 | 0x80));
            if (value >> 21 == 0) {
                buffer[2] = (uint8_t) (value >> 14);
                bytesWritten = 3;
            } else {
                buffer[2] = (uint8_t) (value >> 14 | 0x80);
                if (value >> 28 == 0) {
                    buffer[3] = (uint8_t) (value >> 21);
                    bytesWritten = 4;
                } else {
                    buffer[3] = (uint8_t) (value >> 21 | 0x80);
                    if (value >> 35 == 0) {
                        buffer[4] = (uint8_t) (value >> 28);
                        bytesWritten = 5;
                    } else {
                        buffer[4] = (uint8_t) (value >> 28 | 0x80);
                        if (value >> 42 == 0) {
                            buffer[5] = (uint8_t) (value >> 35);
                            bytesWritten = 6;
                        } else {
                            buffer[5] = (uint8_t) (value >> 35 | 0x80);
                            if (value >> 49 == 0) {
                                buffer[6] = (uint8_t) (value >> 42);
                                bytesWritten = 7;
                            } else {
                                buffer[6] = (uint8_t) (value >> 42 | 0x80);
                                if (value >> 56 == 0) {
                                    buffer[7] = (uint8_t) (value >> 49);
                                    bytesWritten = 8;
                                } else {
                                    buffer[7] = (uint8_t) (value >> 49 | 0x80);
                                    buffer[8] = (uint8_t) (value >> 56);
                                    bytesWritten = 9;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return bytesWritten;
}

/**
 * Decode the next value from a zigzag varint string
 * @param buffer points to next byte to read and decode
 * @param len number of bytes available starting from buffer, must be >0
 * @param retVal where to store the decoded value
 * @return number of bytes read (>0) or -1 if there was a truncation error
 *         (meaning buffer is too short to complete the decoding)
 *         or a value overflow error (value does not fit in 64-bit)
 */
 static int zig_zag_decode_i64(const uint8_t* buffer, int len, int64_t* retVal) {

    int64_t result = 0;
    int shift = 0;
    uint64_t b;
    int read_index = 0;

    while (read_index < len) {
        b = buffer[read_index++];
        result |= ((b & 0x7f) << shift);
        if (((b & 0x80) == 0) || (read_index == 9)) {
            /* At most 9 bytes, the 9th byte is always a full byte (no more bit)
               at this point the max value we can get would fit in 64 bits
               as 8 times 7 bits + 8 = 64
            */
            /* unzigzag the value 0=>0, 1=>-1, 2=>1, 3=>-2, 4=>2 etc...*/
            if (result & 0x1) {
                result = (result >> 1) ^ (~0);
            } else {
                result = result >> 1;
            }
            *retVal = result;
            return read_index;
        }
        shift += 7;
        if (shift >= 64) {
            /* too big to fit */
            return -1;
        }
    }
    /* incomplete buffer */
    return -1;
}

/* Helper functions for reading and writing into various word size arrays */
typedef uint64_t (*get_array_entry)(void *src, int index);

static uint64_t get_array_entry16(void *src, int index) {
    uint16_t *array = src;
    return array[index];
}

static uint64_t get_array_entry32(void *src, int index) {
    uint32_t *array = src;
    return array[index];
}

static uint64_t get_array_entry64(void *src, int index) {
    uint64_t *array = src;
    return array[index];
}

typedef int (*set_array_entry)(void *src, int index, uint64_t value);

static int set_array_entry16(void *src, int index, uint64_t value) {
    uint16_t *array = src;
    if (value > 0xFFFF) {
        return -1;
    }
    array[index] = value;
    return 0;
}

static int set_array_entry32(void *src, int index, uint64_t value) {
    uint32_t *array = src;
    if (value > 0xFFFFFFFF) {
        return -1;
    }
    array[index] = (uint32_t) value;
    return 0;
}

static int set_array_entry64(void *src, int index, uint64_t value) {
    uint64_t *array = src;
    array[index] = value;
    return 0;
}

/**
 * Encodes a counts array of a given size and word size into
 * a varint stream compliant to the HdrHistogram V2 format
 # @return the length of the encoded varint stream in bytes
 */
static PyObject *py_hdr_encode(PyObject *self, PyObject *args) {
    void *vsrc;       /* l: addressof a ctypes c_uint16, c_uint32 or c_uint64 array */
    int max_index;    /* i: encode entries [0..max_index-1] */
    int counts_len;
    uint8_t *dest;    /* l: where to encode */
    int dest_len;     /* i: length of the destination buffer, must be >=(word_size+1)*max_index */
    get_array_entry get_entry;
    int count_loc;
    int bf_len;
    PyObject *res;

    if (!PyArg_ParseTuple(args, "liiili", &vsrc, &max_index, &counts_len, &dest, &dest_len)) {
        return NULL;
    }
    if (vsrc == NULL) {
        PyErr_SetString(PyExc_ValueError, "NULL source array");
        return NULL;
    }
    if (max_index < 0) {
        PyErr_SetString(PyExc_ValueError, "Negative max index");
        return NULL;
    }
    if (max_index == 0) {
        return Py_BuildValue("i", 0);
    }

    get_entry = get_array_entry64;

    if (dest_len < 9 * max_index) {
        PyErr_SetString(PyExc_ValueError, "Negative offset");
        return NULL;
    }
    if (dest == NULL) {
        PyErr_SetString(PyExc_ValueError, "Destination buffer is NULL");
        return NULL;
    }

    bf_len = (counts_len + 7) >> 3;
    count_loc = 0;
    int bf_byte;
    int bit;
    int write_index = bf_len;
    for (bf_byte = 0; bf_byte < bf_len; bf_byte++) {
        char b = 0;

        for (bit = 0; (bit < 8) & (count_loc < max_index); bit++) {
            uint64_t count = get_entry(vsrc, count_loc++);
            if (count != 0) {
                write_index += zig_zag_encode_i64(&dest[write_index], count);
                b |= 1 << bit;
            }
        }
        dest[bf_byte] = b;
    }

    /* write_index is the exact length of the encoded string */
    res = Py_BuildValue("i", bf_len + write_index);
    return res;
}

/**
 * Decodes a character buffer containing a varint stream into
 * a pre-allocated counts array of a given size and word size
 * @return a dictionary
 * { "total":int,"min_nonzero_index":int,"max_nonzero_index":int}
 */
static PyObject *py_hdr_decode(PyObject *self, PyObject *args) {
    uint8_t *src;   /* t#: read only character buffer */
    int src_len;    /*     its length */
    int start_index; /* i: start decoding from this offset, must be < src_len */
    void *vdst;     /* l: address of a counts array */
    int max_index;  /* i: number of entries in that array, must be > 0 */
    int bf_len;
    int count_loc;
    int read_index;

    set_array_entry set_entry;
    uint64_t total_count = 0;
    int64_t min_nonzero_index = -1;
    int64_t max_nonzero_index = 0;

    if (!PyArg_ParseTuple(args, "s#ilii", &src, &src_len,
                          &start_index,
                          &vdst, &max_index)) {
        return NULL;
    }
    if (vdst == NULL) {
        PyErr_SetString(PyExc_ValueError, "NULL destination array");
        return NULL;
    }
    if (start_index < 0) {
        PyErr_SetString(PyExc_IndexError, "Negative starting read index");
        return NULL;
    }
    if (max_index <= 0) {
        PyErr_SetString(PyExc_IndexError, "Negative or null max index");
        return NULL;
    }

    set_entry = set_array_entry64;

    bf_len = (max_index + 7) >> 3;
    read_index = start_index + bf_len;
    src_len -= start_index + sizeof(bf_len);
    count_loc = 0;
    if ((src_len > 0) && src) {
        int bf_byte;
        int bit;
        for (bf_byte = 0; bf_byte < bf_len; bf_byte++) {
            char b = src[start_index + bf_byte];

            for (bit = 0; bit < 8; bit++) {
                int64_t value = 0;

                if ((b & (1 << bit)) != 0) {
                    int read_bytes = zig_zag_decode_i64(&src[read_index], src_len, &value);

                    if (read_bytes < 0) {
                        /* decode error */
                        PyErr_SetString(PyExc_ValueError, "Zigzag varint decoding error");
                        return NULL;
                    }
                    read_index += read_bytes;
                    src_len -= read_bytes;
                }

                if (set_entry(vdst, (int) count_loc, value)) {
                    PyErr_SetString(PyExc_OverflowError, "Value overflows destination counter size");
                    return NULL;
                }
                total_count += value;
                max_nonzero_index = count_loc;
                if (min_nonzero_index < 0) {
                    min_nonzero_index = count_loc;
                }

                if (count_loc >= max_index) {
                    /* overrun */
                    PyErr_Format(PyExc_IndexError, "Destination array overrun index=%d" PRId64 " max index=%d",
                                                   count_loc, max_index);
                    return NULL;
                }

                if (src_len <= 0) {
                    break;
                }

                count_loc++;
            }

            if (src_len <= 0) {
                break;
            }
        }
    }
    return Py_BuildValue("{s:i,s:i,s:i}",
                        "total", total_count,
                        "min_nonzero_index", min_nonzero_index,
                        "max_nonzero_index", max_nonzero_index);
}

/**
 * Adds 1 array into the other. Checks for potential overflow before adding.
 * In case of overflow error the destination array is unmodified.
 */
static PyObject *py_hdr_add_array(PyObject *self, PyObject *args) {
    void *vdst;     /* l: address of destination array first entry */
    void *vsrc;     /* l: address of source array first entry */
    int max_index;  /* i: entries from 0 to max_index-1 are added */
    int64_t total_count = 0;
    
    if (!PyArg_ParseTuple(args, "llii", &vdst, &vsrc, &max_index)) {
        return NULL;
    }
    if (vsrc == NULL) {
        PyErr_SetString(PyExc_ValueError, "NULL source array");
        return NULL;
    }
    if (vdst == NULL) {
        PyErr_SetString(PyExc_ValueError, "NULL destination array");
        return NULL;
    }
    if (max_index < 0) {
        PyErr_SetString(PyExc_ValueError, "Negative max index");
        return NULL;
    }

    uint64_t *src = vsrc;
    uint64_t *dst = vdst;
    int index;
    /* check overflow */
    // for (index=0; index < max_index; ++index) {
    //     uint64_t value = src[index];
    //     if (value && ((dst[index] + value) < dst[index])) {
    //         PyErr_SetString(PyExc_OverflowError, "64-bit overflow");
    //         return NULL;
    //     }
    // }
    for (index=0; index < max_index; ++index) {
        int64_t value = src[index];
        if (value) {
            dst[index] += value;
            total_count += value;
        }
    }
    return Py_BuildValue("i", total_count);
}

/**
 * Adds 1 array into the other. Checks for potential overflow before adding.
 * In case of overflow error the destination array is unmodified.
 */
static PyObject *py_hdr_sub_array(PyObject *self, PyObject *args) {
    void *vdst;     /* l: address of destination array first entry */
    void *vsrc;     /* l: address of source array first entry */
    int max_index;  /* i: entries from 0 to max_index-1 are added */
    int64_t total_count = 0;
    
    if (!PyArg_ParseTuple(args, "llii", &vdst, &vsrc, &max_index)) {
        return NULL;
    }
    if (vsrc == NULL) {
        PyErr_SetString(PyExc_ValueError, "NULL source array");
        return NULL;
    }
    if (vdst == NULL) {
        PyErr_SetString(PyExc_ValueError, "NULL destination array");
        return NULL;
    }
    if (max_index < 0) {
        PyErr_SetString(PyExc_ValueError, "Negative max index");
        return NULL;
    }

    uint64_t *src = vsrc;
    uint64_t *dst = vdst;
    int index;
    /* check overflow */
    // for (index=0; index < max_index; ++index) {
    //     uint64_t value = src[index];
    //     if (value && ((dst[index] + value) < dst[index])) {
    //         PyErr_SetString(PyExc_OverflowError, "64-bit overflow");
    //         return NULL;
    //     }
    // }
    for (index=0; index < max_index; ++index) {
        int64_t value = src[index];
        if (value) {
            dst[index] -= value;
            total_count -= value;
        }
    }

    return Py_BuildValue("i", total_count);
}

#define ENCODE_DOCSTRING "Encode a counts array into a V2 varint buffer"
#define DECODE_DOCSTRING "Decode a V2 varint buffer into a counts array"
#define ADD_ARRAY_DOCSTRING "Add a counts array to another"
#define SUB_ARRAY_DOCSTRING "Subtract a counts array from another"

static PyMethodDef HdrhMethods[] = {
    {"encode",  py_hdr_encode, METH_VARARGS, ENCODE_DOCSTRING},
    {"decode",  py_hdr_decode, METH_VARARGS, DECODE_DOCSTRING},
    {"add_array",  py_hdr_add_array, METH_VARARGS, ADD_ARRAY_DOCSTRING},
    {"sub_array",  py_hdr_sub_array, METH_VARARGS, SUB_ARRAY_DOCSTRING},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3
    static struct PyModuleDef hdrhdef = {
        PyModuleDef_HEAD_INIT,
        "pyhdrh",            /* m_name */
        NULL,                /* m_doc */
        -1,                  /* m_size */
        HdrhMethods,         /* m_methods */
        NULL,                /* m_reload */
        NULL,                /* m_traverse */
        NULL,                /* m_clear */
        NULL,                /* m_free */
    };

    PyMODINIT_FUNC PyInit_pyhdrh(void) {
        return PyModule_Create(&hdrhdef);
    }
#else
    PyMODINIT_FUNC initpyhdrh(void) {
        (void) Py_InitModule("pyhdrh", HdrhMethods);
    }
#endif
