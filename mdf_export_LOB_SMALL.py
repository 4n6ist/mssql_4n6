#!/usr/bin/env python
# coding=utf-8

# extract_mdf_LOB_SMALL.py
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

class RecordHeaderType3_4(LittleEndianStructure):
    _pack_ = 1
    _fields_ = (
        ('status', c_int8),
        ('unknown1', c_int8),
        ('length', c_uint16),
        ('blobid', c_int64),
        ('type', c_uint16)
    )
    def print_info(self):
        print("RecordHeader")
        print(" Status: {0}".format(self.status))
        print(" Length: {0}".format(self.length))
        print(" BlobId: {0}".format(self.blobid))
        print(" Type: {0}".format(self.type))

def print_SMALLROOT_from_slotnum(input_file, offset, slot):
    phdr = PageHeader()
    input_file.seek(offset)
    input_file.readinto(phdr)
    rhdr = RecordHeaderType3_4()
    slot_offset = 96 # fixed offset of first slot 
    if slot != 0:
        i=0
        while slot_offset < phdr.freeData:
            input_file.seek(offset+slot_offset)
            input_file.readinto(rhdr)        
            if rhdr.length == 14: # irregular handling
                slot_offset += rhdr.length
                continue
            slot_offset += rhdr.length
            i += 1
            if i == slot:
                break
    input_file.seek(offset+slot_offset)
    input_file.readinto(rhdr)
    if rhdr.type != 0: # SMALL_ROOT
        print("ERROR: Specified Page&Slot is not SMALL_ROOT")
        sys.exit()
    size = struct.unpack("<H", input_file.read(2))[0]
    input_file.seek(4,1)
    data = input_file.read(size)
    print(data)

def main():
    parser = argparse.ArgumentParser(description="Extract LOB SMALL_ROOT data from specified Page&Slot")
    parser.add_argument('-i', '--input', action='store', type=str, required=True, help='path to MDF file')
    parser.add_argument('-p', '--page', action='store', type=int, required=True, help='PageNum')
    parser.add_argument('-s', '--slot', action='store', type=int, required=True, help='SlotNum')
    args = parser.parse_args()

    if os.path.exists(os.path.abspath(args.input)):
        input_file = open(args.input, "rb")
        input_size = os.path.getsize(args.input)
    else:
        sys.exit("{0} does not exist.".format(args.input))

    offset = args.page * 0x2000
    print_SMALLROOT_from_slotnum(input_file, offset, args.slot)

if __name__ == "__main__":
    main()

