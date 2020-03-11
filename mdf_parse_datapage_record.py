#!/usr/bin/env python
# coding=utf-8

# mdf_parse_datapage_record.py
#
# Copyright 2020 4n6ist
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import argparse
import struct
import binascii
from ctypes import *

# https://improve.dk/reverse-engineering-sql-server-page-headers/
class PageHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = (
        ('headerVer', c_int8),
        ('type', c_int8),
        ('typeFlag', c_uint8),
        ('level', c_int8),
        ('flag', c_uint16),
        ('indexId', c_int16),
        ('prevPageId', c_int32),
        ('prevFileId', c_int16),
        ('pminlen', c_int16),
        ('nextPageId', c_int32),
        ('nextFileId', c_int16),
        ('slotCnt', c_int16),
        ('objId', c_int32),
        ('freeCnt', c_int16),
        ('freeData', c_int16),
        ('pageId', c_int32),
        ('fileId', c_int16),
        ('reservedCnt', c_int16),
        ('lsn1', c_int32),
        ('lsn2', c_int32),
        ('lsn3', c_int16),
        ('xactReserved', c_int16),
        ('xdesId2', c_int32),
        ('xdesId1', c_int16),
        ('ghostRecCnt', c_int16),
        ('unknown', c_char * 36)    
    )
    def __init__(self):
        self.unknown = b'\x00'

class RecordHeaderType1(LittleEndianStructure):
    _pack_ = 1
    _fields_ = (
        ('status', c_int8),
        ('unknown1', c_int8),
        ('offset', c_uint16)
    )

# Ref. https://qiita.com/taka_baya/items/c22bd5f5e7cb3de90988 - start
def read_bytes(input):
    # extract input data of each 1byte     
    for b in input:
        yield b

def is_character_printable(s):
    # return true if a character is readable
    if s < 126 and s >= 33:
        return True 

def validate_byte_as_printable(byte):
    # no ascii character display as '.'
    if is_character_printable(byte):
        return byte
    else:
        return 46

def print_hex(data):
    memory_address = 0
    ascii_string = ""

    # display data until EOF
    for byte in read_bytes(data):
        ascii_string = ascii_string + chr(validate_byte_as_printable(byte))
        if memory_address%16 == 0:
            print(format(memory_address, '06X'), end='')
            print(" " + hex(byte)[2:].zfill(2), end='')
        elif memory_address%16 == 15:
            print(" " + hex(byte)[2:].zfill(2), end='')
            print(" " + ascii_string)
            ascii_string = ""
        else:
            print(" " + hex(byte)[2:].zfill(2), end='')
        memory_address = memory_address + 1

    # print ascii for last line
    if len(data)%16 != 0:
        padding = 16 - len(data)%16
        print("   " * padding, end='')
        print(" " + ascii_string)
# Ref. - end

def print_hex_for_specified_slot(input_file, offset, slot_offsets, i, deleted):
    print("")
    if deleted:
        print("[DELETED] Offset:{0}, Slot:{1}".format(slot_offsets[i],i))
    else:
        print("Offset:{0}, Slot:{1}".format(slot_offsets[i],i))
    input_file.seek(offset+slot_offsets[i])
    length=slot_offsets[i+1]-slot_offsets[i]
    data = input_file.read(length)
    print_hex(data)
    print("")

# Example: 4n6ist_simple.mdf - pictures table
# id: int, date:char(8), category:nchar(16), filename:nvarchar(255), data:image
def print_for_specific_table(input_file, offset, slot_offsets, i):    

    # 4 = 1(StatusBit) + 1(Unused) + 2(Offset to Num of Column)
    input_file.seek(offset+slot_offsets[i]+4)
    id = struct.unpack("<I", input_file.read(4))[0]
    input_file.seek(offset+slot_offsets[i]+8)
    date = input_file.read(8)
    input_file.seek(offset+slot_offsets[i]+16)
    category = input_file.read(32)
    # 48 = 4 + 4(id) + 8(date) + 32(category)

    # 53 = 48 + 2(Num of Column) + 1(Null Bitmap) + 2(Num of Variable Column)
    input_file.seek(offset+slot_offsets[i]+53)
    filename_offset = struct.unpack("<H", input_file.read(2))[0]
    data_offset = struct.unpack("<H", input_file.read(2))[0]
    data_offset = data_offset & 0x1fff
 
    # 57 = 53 + 2(filename_offset) + 2(data_offset)
    filename_length = filename_offset - 57
    input_file.seek(offset+slot_offsets[i]+57)
    filename = input_file.read(filename_length)

    input_file.seek(offset+slot_offsets[i]+data_offset-8)
    data_Page = struct.unpack("<I", input_file.read(4))[0]
    data_File = struct.unpack("<H", input_file.read(2))[0]
    data_Slot = struct.unpack("<H", input_file.read(2))[0]

    print("id: {0}".format(id))
    print("date: {0}".format(date.decode('ascii')))
    print("Category: {0}".format(category.decode('utf-16')))
    print("Filename: {0}".format(filename.decode('utf-16')))
    print("Data: {0}, {1}, {2} (Page, File, Slot)".format(data_Page,data_File,data_Slot))

def parse_mdf_Type1_record(input_file, offset, deleted):
    phdr = PageHeader()
    input_file.seek(offset)
    input_file.readinto(phdr)
    if phdr.type != 1:
        print("ERROR: Specified page is not data page")
        sys.exit()

    rhdr = RecordHeaderType1()

    # create offset list from slot array (offset 0 means deleted slot(record))
    slot_array_offsets = []
    for i in range(phdr.slotCnt): 
        input_file.seek(offset+0x2000-(2*i)-2)
        slot_array_offset = struct.unpack("<H", input_file.read(2))[0]
        slot_array_offsets.append(slot_array_offset)

    # create offset list based on each slot until freeData
    slot_offsets = []
    slot_offset = 96 # fixed offset of first slot 
    slot_offsets.append(slot_offset)
    while slot_offset < phdr.freeData: 
        input_file.seek(offset+slot_offset)
        input_file.readinto(rhdr)
        input_file.seek(offset+slot_offset+rhdr.offset)
        num_of_columns = struct.unpack("<H", input_file.read(2))[0]
        input_file.seek(1+num_of_columns//8,1) # skip Null Bitmap
        num_of_vcolumns = struct.unpack("<H", input_file.read(2))[0]
        v_offsets = []
        for j in range(num_of_vcolumns):
            v_offset = struct.unpack("<H", input_file.read(2))[0]
            v_offset = v_offset & 0x1fff # exclude most significant 3 bit (looks like these bits represent flag)
            v_offsets.append(v_offset)
        slot_offset += v_offsets[-1]
        slot_offsets.append(slot_offset)

    print("slotCnt: {0}, ".format(phdr.slotCnt),end='')
    print("freeData {0}, ".format(phdr.freeData),end='')
    print("slotArray: {0}, ".format(len(slot_array_offsets)),end='')
    print("actualSlots: {0}".format(len(slot_offsets)-1))

    # Compare with lists between slot_offsets and slot_array_offsets
    i=0
    j=0
    while j < len(slot_array_offsets):
        if slot_offsets[i] == slot_array_offsets[j]:
            if not deleted:                
                print_hex_for_specified_slot(input_file, offset, slot_offsets, i, False)
                #print_for_specific_table(input_file, offset, slot_offsets, i)            
            j += 1
        else:
            print_hex_for_specified_slot(input_file, offset, slot_offsets, i, True)
            #print_for_specific_table(input_file, offset, slot_offsets, i)
            if slot_array_offsets[j] == 0:
                j += 1
        i += 1

    while i < len(slot_offsets)-1:
        print_hex_for_specified_slot(input_file, offset, slot_offsets, i, True)
        print_for_specific_table(input_file, offset, slot_offsets, i)
        i += 1

def main():
    parser = argparse.ArgumentParser(description="Parse&Find Record of data page in MDF.")
    parser.add_argument('-i', '--input', action='store', type=str, required=True, help='path to MDF file')
    parser.add_argument('-p', '--page', action='store', type=int, required=True, help='PageNum')
    parser.add_argument('-d', '--deleted', action='store_true', default=False, help='display only deleted records')
    args = parser.parse_args()

    if os.path.exists(os.path.abspath(args.input)):
        input_file = open(args.input, "rb")
    else:
        sys.exit("{0} does not exist.".format(args.input))

    offset = args.page * 0x2000
    parse_mdf_Type1_record(input_file, offset, args.deleted)

if __name__ == "__main__":
    main()
