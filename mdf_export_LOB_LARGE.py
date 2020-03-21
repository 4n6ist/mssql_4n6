#!/usr/bin/env python
# coding=utf-8

# extract_mdf_LOB_LARGE.py
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

# Global - all of leaf page&slot lists specified by Page&Slot LOB
leaf_page_list = []
leaf_slot_list = []

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

class LobLargeRootHeader(LittleEndianStructure):
    _pack_ = 2
    _fields_ = (
        ('maxlinks', c_uint16),
        ('curlinks', c_uint16),
        ('level', c_uint16),
        ('unknown', c_uint32)
    )
    def print_info(self):
        print("LargeRoot")    
        print(" MaxLinks: {0}".format(self.maxlinks))
        print(" CurLinks: {0}".format(self.curlinks))
        print(" Level: {0}".format(self.level))
        
class LobLargeRootBody(LittleEndianStructure):
    _pack_ = 2
    _fields_ = (
        ('size', c_uint32),
        ('page', c_uint32),
        ('fileid', c_uint16),
        ('slot', c_uint16)
    )
    def print_info(self):
        print("  Size: {0}".format(self.size))
        print("  Page: {0}".format(self.page))
        print("  Slot: {0}".format(self.slot))

class LobInternalHeader(LittleEndianStructure):
    _pack_ = 2
    _fields_ = (
        ('maxlinks', c_uint16),
        ('curlinks', c_uint16),
        ('level', c_uint16)
    )
    def print_info(self):
        print("Child")
        print(" MaxLinks: {0}".format(self.maxlinks))
        print(" CurLinks: {0}".format(self.curlinks))
        print(" Level: {0}".format(self.level))

class LobInternalBody(LittleEndianStructure):
    _pack_ = 2
    _fields_ = (
        ('offset', c_uint32),
        ('unknown', c_int32),
        ('page', c_uint32),
        ('fileid', c_uint16),
        ('slot', c_int16)
    )
    def print_info(self):
        print(self.offset, self.page, self.fileid, self.slot)
    
def get_offset_from_slotnum(input_file, offset, slot):
    phdr = PageHeader()
    input_file.seek(offset)
    input_file.readinto(phdr)
    if slot == 0:
        return 96
    rhdr = RecordHeaderType3_4()
    slot_offset = 96 # fixed offset of first slot 
    i=0
    while i < phdr.slotCnt:
        input_file.seek(offset+slot_offset)
        input_file.readinto(rhdr)
        if rhdr.length == 14: # irregular handling
            slot_offset += rhdr.length
            continue
        slot_offset += rhdr.length
        i += 1
        if i == slot:
            break        
    return slot_offset

def get_leaf_pages_from_root(input_file, offset, rel_offset):
    internal_page_list = []
    rhdr = RecordHeaderType3_4()
    llrhdr = LobLargeRootHeader()
    llrbody = LobLargeRootBody()

    input_file.seek(offset+rel_offset)
    input_file.readinto(rhdr)
    rhdr.print_info()
    if rhdr.type != 5: # LARGE_ROOT
        print("ERROR: Specified Page&Slot is not LARGE_ROOT")
        sys.exit()

    input_file.seek(offset+rel_offset+14)
    input_file.readinto(llrhdr)
    llrhdr.print_info()

    for i in range(llrhdr.curlinks):
        input_file.readinto(llrbody)
        if llrbody.slot != 0:
            print("Found irregular Slot. Need additional implementation.")
        if llrbody.fileid != 1:
            print("Found irregular FileID. Need additional implementation.")                
        internal_page_list.append(llrbody.page)
        llrbody.print_info()

    for page in internal_page_list: # from root to leaf
        create_leaf_list(input_file, page)

    return

def create_leaf_list(input_file, page):
    rhdr = RecordHeaderType3_4()
    lihdr = LobInternalHeader()
    libody = LobInternalBody()

    offset = int(page) * 0x2000
    input_file.seek(offset+96)
    input_file.readinto(rhdr)
    rhdr.print_info()

    input_file.seek(offset+110) # 96(page hdr) + 14(rec3/4 hdr) 
    input_file.readinto(lihdr)
    lihdr.print_info()

    if lihdr.maxlinks != 501:
        print("Found irregular MaxLinks. Need additional implementation.")

    if lihdr.level != 0: # node
        for i in range(lihdr.curlinks):
            input_file.seek(offset+116+16*i) # 110 (pagehdr,rec3/4hdr) + 6(LOB hdr) + 16(LOB body) * i
            input_file.readinto(libody)
            if libody.fileid != 1:
                print("Found irregular FileID. Need additional implementation.")
            create_leaf_list(input_file, libody.page) # recursive until leaf
    else: # leaf
        for j in range(lihdr.curlinks):
            input_file.seek(offset+116+16*j)
            input_file.readinto(libody)
            if libody.fileid != 1:
                print("Found irregular FileID. Need additional implementation.")
            leaf_page_list.append(libody.page)
            leaf_slot_list.append(libody.slot)
    return

def write_data_from_leaf_lists(input_file, output_file, page_list, slot_list):
    rhdr = RecordHeaderType3_4()
    size = 0
    i = 0
    for page in page_list:
        offset = int(page) * 0x2000
        slot_offset = 96 # slot 0 offset
        if slot_list[i] != 0: # seek slot_offset if slot > 0
            j = 0
            while j < slot_list[i]:
                input_file.seek(offset+slot_offset)
                input_file.readinto(rhdr)
                if rhdr.length == 14: # irregular handling
                    slot_offset += rhdr.length
                    continue
                slot_offset += rhdr.length
                j += 1
            input_file.seek(offset+slot_offset)
            input_file.readinto(rhdr)
            while rhdr.length == 14: # irregular handling for last slot
                slot_offset += rhdr.length
                input_file.seek(offset+slot_offset)
                input_file.readinto(rhdr)
        input_file.seek(offset+slot_offset)
        input_file.readinto(rhdr)
        if rhdr.type != 3: # DATA
            print("Specified Page&Slot is not LARGE_ROOT. Need additional implementation.")
        data = input_file.read(rhdr.length-14)
        output_file.write(data)
        i += 1
        size += len(data)
    return size

def main():
    parser = argparse.ArgumentParser(description="Extract LOB DATA from specified LARGE_ROOT_YUKON(Record Type 5) Page&Slot")
    parser.add_argument('-i', '--input', action='store', type=str, required=True, help='path to MDF file')
    parser.add_argument('-o', '--output', action='store', type=str, required=True, help='path to output file')
    parser.add_argument('-p', '--page', action='store', type=int, required=True, help='PageNum')
    parser.add_argument('-s', '--slot', action='store', type=int, required=True, help='SlotNum')
    args = parser.parse_args()

    if os.path.exists(os.path.abspath(args.input)):
        input_file = open(args.input, "rb")
        input_size = os.path.getsize(args.input)
    else:
        sys.exit("ERROR: {0} does not exist.".format(args.input))

    offset = args.page * 0x2000
    rel_offset = get_offset_from_slotnum(input_file, offset, args.slot)
    print("Page {0}, Slot {1} => Offset {2}".format(args.page, args.slot, rel_offset))
    get_leaf_pages_from_root(input_file, offset, rel_offset)
    output_file = open(args.output, "ab")        
    size = write_data_from_leaf_lists(input_file, output_file, leaf_page_list, leaf_slot_list)
    print("Wrote {0} bytes".format(size))

if __name__ == "__main__":
    main()

