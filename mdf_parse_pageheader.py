#!/usr/bin/env python
# coding=utf-8

# mdf_parse_pageheader.py
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
        
def parse_mdf_pageheaders(input_file, input_size, leaf):
    phdr = PageHeader()
    offset = 0
    while offset < input_size:
        input_file.seek(offset)
        input_file.readinto(phdr)
        if not leaf or phdr.type == 1:
            print(phdr.pageId, phdr.type, phdr.typeFlag, phdr.level, phdr.flag, phdr.pminlen, phdr.slotCnt, phdr.freeCnt, phdr.freeData, phdr.reservedCnt, phdr.ghostRecCnt, sep=',')
        offset += 0x2000

def main():
    parser = argparse.ArgumentParser(description="Parse MDF Page Header")
    parser.add_argument('-i', '--input', action='store', type=str, required=True, help='path to MDF file')
    parser.add_argument('-l', '--leaf', action='store_true', default=False, help='display only leaf page')
    args = parser.parse_args()

    if os.path.exists(os.path.abspath(args.input)):
        input_file = open(args.input, "rb")
        input_size = os.path.getsize(args.input)
    else:
        sys.exit("{0} does not exist.".format(args.input))

    print("pageId", "type", "typeFlag", "level", "flag", "pminlen", "slotCnt", "freeCnt", "freeData", "reservedCnt", "ghostRecCnt", sep=',')
    parse_mdf_pageheaders(input_file, input_size, args.leaf)

if __name__ == "__main__":
    main()
