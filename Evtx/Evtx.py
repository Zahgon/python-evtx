#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v.0.3.0
from __future__ import absolute_import

import re
import sys
import mmap
import logging
import binascii
from functools import wraps

import Evtx.Views as e_views

from .Nodes import RootNode, TemplateNode, NameStringNode
from .BinaryParser import Block, ParseException

logger = logging.getLogger(__name__)


class InvalidRecordException(ParseException):
    def __init__(self):
        super(InvalidRecordException, self).__init__("Invalid record structure")


class Evtx(object):
    """
    A convenience class that makes it easy to open an
      EVTX file and start iterating the important structures.
    Note, this class must be used in a context statement
       (see the `with` keyword).
    Note, this class will mmap the target file, so ensure
      your platform supports this operation.
    """

    def __init__(self, filename):
        """
        @type filename:  str
        @param filename: A string that contains the path
          to the EVTX file to open.
        """
        self._filename = filename
        self._buf = None
        self._f = None
        self._fh = None

    def __enter__(self):
        self._f = open(self._filename, "rb")
        self._buf = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        self._fh = FileHeader(self._buf, 0x0)
        return self

    def __exit__(self, type, value, traceback):
        self._buf.close()
        self._f.close()
        self._fh = None

    def ensure_contexted(func):
        """
        This decorator ensure that an instance of the
          Evtx class is used within a context statement.  That is,
          that the `with` statement is used, or `__enter__()`
          and `__exit__()` are called explicitly.
        """
        pass

    @ensure_contexted
    def chunks(self):
        """
        Get each of the ChunkHeaders from within this EVTX file.

        @rtype generator of ChunkHeader
        @return A generator of ChunkHeaders from this EVTX file.
        """
        pass

    @ensure_contexted
    def records(self):
        """
        Get each of the Records from within this EVTX file.

        @rtype generator of Record
        @return A generator of Records from this EVTX file.
        """
        pass

    @ensure_contexted
    def get_record(self, record_num):
        """
        Get a Record by record number.

        @type record_num:  int
        @param record_num: The record number of the the record to fetch.
        @rtype Record or None
        @return The record request by record number, or None if
          the record is not found.
        """
        pass

    @ensure_contexted
    def get_file_header(self):
        pass


class FileHeader(Block):
    def __init__(self, buf, offset):
        logger.debug("FILE HEADER at {}.".format(hex(offset)))
        super(FileHeader, self).__init__(buf, offset)
        self.declare_field("string", "magic", 0x0, length=8)
        self.declare_field("qword", "oldest_chunk")
        self.declare_field("qword", "current_chunk_number")
        self.declare_field("qword", "next_record_number")
        self.declare_field("dword", "header_size")
        self.declare_field("word", "minor_version")
        self.declare_field("word", "major_version")
        self.declare_field("word", "header_chunk_size")
        self.declare_field("word", "chunk_count")
        self.declare_field("binary", "unused1", length=0x4C)
        self.declare_field("dword", "flags")
        self.declare_field("dword", "checksum")

    def __repr__(self):
        return "FileHeader(buf={!r}, offset={!r})".format(self._buf, self._offset)

    def __str__(self):
        return "FileHeader(offset={})".format(hex(self._offset))

    def check_magic(self):
        """
        @return A boolean that indicates if the first eight bytes of
          the FileHeader match the expected magic value.
        """
        pass

    def calculate_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum off the first 0x78 bytes.
          This is consistent with the checksum stored by the FileHeader.
        """
        pass

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader
          successfully passes a set of heuristic checks that
          all EVTX FileHeaders should pass.
        """
        pass

    def is_dirty(self):
        """
        @return A boolean that indicates that the log has been
          opened and was changed, though not all changes might be
          reflected in the file header.
        """
        pass

    def is_full(self):
        """
        @return A boolean that indicates that the log
          has reached its maximum configured size and the retention
          policy in effect does not allow to reclaim a suitable amount
          of space from the oldest records and an event message could
          not be written to the log file.
        """
        pass

    def first_chunk(self):
        """
        @return A ChunkHeader instance that is the first chunk
          in the log file, which is always found directly after
          the FileHeader.
        """
        pass

    def current_chunk(self):
        """
        @return A ChunkHeader instance that is the current chunk
          indicated by the FileHeader.
        """
        pass

    def chunks(self, include_inactive=False):
        """
        @return A generator that yields the chunks of the log file
          starting with the first chunk, which is always found directly
          after the FileHeader.

        If `include_inactive` is set to true, enumerate chunks beyond those
        declared in the file header (and may therefore be corrupt).
        """
        pass

    def get_record(self, record_num):
        """
        Get a Record by record number.

        @type record_num:  int
        @param record_num: The record number of the the record to fetch.
        @rtype Record or None
        @return The record request by record number, or None if the
          record is not found.
        """
        pass


class Template(object):
    def __init__(self, template_node):
        self._template_node = template_node
        self._xml = None

    def _load_xml(self):
        """
        TODO(wb): One day, nodes should generate format strings
          instead of the XML format made-up abomination.
        """
        pass

    def make_substitutions(self, substitutions):
        """

        @type substitutions: list of VariantTypeNode
        """
        pass

    def node(self):
        pass


class ChunkHeader(Block):
    def __init__(self, buf, offset):
        logger.debug("CHUNK HEADER at {}.".format(hex(offset)))
        super(ChunkHeader, self).__init__(buf, offset)
        self._strings = None
        self._templates = None

        self.declare_field("string", "magic", 0x0, length=8)
        self.declare_field("qword", "file_first_record_number")
        self.declare_field("qword", "file_last_record_number")
        self.declare_field("qword", "log_first_record_number")
        self.declare_field("qword", "log_last_record_number")
        self.declare_field("dword", "header_size")
        self.declare_field("dword", "last_record_offset")
        self.declare_field("dword", "next_record_offset")
        self.declare_field("dword", "data_checksum")
        self.declare_field("binary", "unused", length=0x44)
        self.declare_field("dword", "header_checksum")

    def __repr__(self):
        return "ChunkHeader(buf={!r}, offset={!r})".format(self._buf, self._offset)

    def __str__(self):
        return "ChunkHeader(offset={})".format(hex(self._offset))

    def check_magic(self):
        """
        @return A boolean that indicates if the first eight bytes of
          the ChunkHeader match the expected magic value.
        """
        pass

    def calculate_header_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum of the ChunkHeader fields.
        """
        pass

    def calculate_data_checksum(self):
        """
        @return A integer in the range of an unsigned int that
          is the calculated CRC32 checksum of the Chunk data.
        """
        pass

    def verify(self):
        """
        @return A boolean that indicates that the FileHeader
          successfully passes a set of heuristic checks that
          all EVTX ChunkHeaders should pass.
        """
        pass

    def _load_strings(self):
        pass

    def strings(self):
        """
        @return A dict(offset --> NameStringNode)
        """
        pass

    def add_string(self, offset, parent=None):
        """
        @param offset An integer offset that is relative to the start of
          this chunk.
        @param parent (Optional) The parent of the newly created
           NameStringNode instance. (Default: this chunk).
        @return None
        """
        pass

    def _load_templates(self):
        """
        @return None
        """
        pass

    def add_template(self, offset, parent=None):
        """
        @param offset An integer which contains the chunk-relative offset
           to a template to load into this Chunk.
        @param parent (Optional) The parent of the newly created
           TemplateNode instance. (Default: this chunk).
        @return Newly added TemplateNode instance.
        """
        pass

    def templates(self):
        """
        @return A dict(offset --> Template) of all encountered
          templates in this Chunk.
        """
        pass

    def first_record(self):
        pass

    def records(self):
        pass


class Record(Block):
    def __init__(self, buf, offset, chunk):
        logger.debug("Record at {}.".format(hex(offset)))
        super(Record, self).__init__(buf, offset)
        self._chunk = chunk

        self.declare_field("dword", "magic", 0x0)  # 0x00002a2a
        self.declare_field("dword", "size")
        self.declare_field("qword", "record_num")
        self.declare_field("filetime", "timestamp")

        if self.size() > 0x10000:
            raise InvalidRecordException()

        self.declare_field("dword", "size2", self.size() - 4)

    def __repr__(self):
        return "Record(buf={!r}, offset={!r})".format(self._buf, self._offset)

    def __str__(self):
        return "Record(offset={})".format(hex(self._offset))

    def root(self):
        pass

    def length(self):
        pass

    def verify(self):
        pass

    def data(self):
        """
        Return the raw data block which makes up this record as a bytestring.

        @rtype str
        @return A string that is a copy of the buffer that makes
          up this record.
        """
        pass

    def xml(self):
        """
        render the record into XML.
        does not include the xml declaration header.

        Returns:
          str: the rendered xml document.
        """
        pass

    def lxml(self):
        """
        render the record into a lxml document.
        this is useful for querying data from the record using xpath, etc.

        note: lxml must be installed.

        Returns:
          lxml.etree.ElementTree: the rendered and parsed xml document.

        Raises:
          ImportError: if lxml is not installed.
        """
        pass
