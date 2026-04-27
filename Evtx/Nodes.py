#!/usr/bin/python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin william.ballenthin@mandiant.com>
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
from __future__ import absolute_import

import re
import base64
import itertools

import hexdump

from .BinaryParser import Block, ParseException, memoize


class SYSTEM_TOKENS:
    EndOfStreamToken = 0x00
    OpenStartElementToken = 0x01
    CloseStartElementToken = 0x02
    CloseEmptyElementToken = 0x03
    CloseElementToken = 0x04
    ValueToken = 0x05
    AttributeToken = 0x06
    CDataSectionToken = 0x07
    EntityReferenceToken = 0x08
    ProcessingInstructionTargetToken = 0x0A
    ProcessingInstructionDataToken = 0x0B
    TemplateInstanceToken = 0x0C
    NormalSubstitutionToken = 0x0D
    ConditionalSubstitutionToken = 0x0E
    StartOfStreamToken = 0x0F


class NODE_TYPES:
    NULL = 0x00
    WSTRING = 0x01
    STRING = 0x02
    SIGNED_BYTE = 0x03
    UNSIGNED_BYTE = 0x04
    SIGNED_WORD = 0x05
    UNSIGNED_WORD = 0x06
    SIGNED_DWORD = 0x07
    UNSIGNED_DWORD = 0x08
    SIGNED_QWORD = 0x09
    UNSIGNED_QWORD = 0x0A
    FLOAT = 0x0B
    DOUBLE = 0x0C
    BOOLEAN = 0x0D
    BINARY = 0x0E
    GUID = 0x0F
    SIZE = 0x10
    FILETIME = 0x11
    SYSTEMTIME = 0x12
    SID = 0x13
    HEX32 = 0x14
    HEX64 = 0x15
    BXML = 0x21
    WSTRINGARRAY = 0x81


node_dispatch_table = []  # updated at end of file
node_readable_tokens = []  # updated at end of file


class SuppressConditionalSubstitution(Exception):
    """
    This exception is to be thrown to indicate that a conditional
      substitution evaluated to NULL, and the parent element should
      be suppressed. This exception should be caught at the first
      opportunity, and must not propagate far up the call chain.

    Strategy:
      AttributeNode catches this, .xml() --> ""
      StartOpenElementNode catches this for each child, ensures
        there's at least one useful value.  Or, .xml() --> ""
    """

    def __init__(self, msg):
        super(SuppressConditionalSubstitution, self).__init__(msg)


class UnexpectedStateException(ParseException):
    """
    UnexpectedStateException is an exception to be thrown when the parser
      encounters an unexpected value or state. This probably means there
      is a bug in the parser, but could stem from a corrupted input file.
    """

    def __init__(self, msg):
        super(UnexpectedStateException, self).__init__(msg)


class BXmlNode(Block):

    def __init__(self, buf, offset, chunk, parent):
        super(BXmlNode, self).__init__(buf, offset)
        self._chunk = chunk
        self._parent = parent

    def __repr__(self):
        return "BXmlNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "BXmlNode(offset={})".format(hex(self.offset()))

    def dump(self):
        pass

    def tag_length(self):
        """
        This method must be implemented and overridden for all BXmlNodes.
        @return An integer specifying the length of this tag, not including
          its children.
        """
        raise NotImplementedError("tag_length not implemented for {!r}").format(self)

    def _children(self, max_children=None, end_tokens=[SYSTEM_TOKENS.EndOfStreamToken]):
        """
        @return A list containing all of the children BXmlNodes.
        """
        pass

    @memoize
    def children(self):
        pass

    @memoize
    def length(self):
        """
        @return An integer specifying the length of this tag and all
          its children.
        """
        pass

    @memoize
    def find_end_of_stream(self):
        pass


class NameStringNode(BXmlNode):
    def __init__(self, buf, offset, chunk, parent):
        super(NameStringNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("dword", "next_offset", 0x0)
        self.declare_field("word", "hash")
        self.declare_field("word", "string_length")
        self.declare_field("wstring", "string", length=self.string_length())

    def __repr__(self):
        return "NameStringNode(buf={!r}, offset={!r}, chunk={!r})".format(self._buf, self.offset(), self._chunk)

    def __str__(self):
        return "NameStringNode(offset={}, length={}, end={})".format(
            hex(self.offset()), hex(self.length()), hex(self.offset() + self.length())
        )

    def string(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        # two bytes unaccounted for...
        pass


class TemplateNode(BXmlNode):
    def __init__(self, buf, offset, chunk, parent):
        super(TemplateNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("dword", "next_offset", 0x0)
        self.declare_field("dword", "template_id")
        self.declare_field("guid", "guid", 0x04)  # unsure why this overlaps
        self.declare_field("dword", "data_length")

    def __repr__(self):
        return "TemplateNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "TemplateNode(offset={}, guid={}, length={})".format(hex(self.offset()), self.guid(), hex(self.length()))

    def tag_length(self):
        pass

    def length(self):
        pass


class EndOfStreamNode(BXmlNode):
    """
    The binary XML node for the system token 0x00.

    This is the "end of stream" token. It may never actually
      be instantiated here.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(EndOfStreamNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "EndOfStreamNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "EndOfStreamNode(offset={}, length={}, token={})".format(hex(self.offset()), hex(self.length()), 0x00)

    def flags(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        pass

    def children(self):
        pass


class OpenStartElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x01.

    This is the "open start element" token.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(OpenStartElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "unknown0")
        # TODO(wb): use this size() field.
        self.declare_field("dword", "size")
        self.declare_field("dword", "string_offset")
        self._tag_length = 11
        self._element_type = 0

        if self.flags() & 0x04:
            self._tag_length += 4

        if self.string_offset() > self.offset() - self._chunk._offset:
            new_string = self._chunk.add_string(self.string_offset(), parent=self)
            self._tag_length += new_string.length()

    def __repr__(self):
        return "OpenStartElementNode(buf={!r}, offset={!r}, chunk={!r})".format(self._buf, self.offset(), self._chunk)

    def __str__(self):
        return "OpenStartElementNode(offset={}, name={}, length={}, token={}, end={}, taglength={}, endtag={})".format(
            hex(self.offset()),
            self.tag_name(),
            hex(self.length()),
            hex(self.token()),
            hex(self.offset() + self.length()),
            hex(self.tag_length()),
            hex(self.offset() + self.tag_length()),
        )

    @memoize
    def is_empty_node(self):
        pass

    def flags(self):
        pass

    @memoize
    def tag_name(self):
        pass

    def tag_length(self):
        pass

    def verify(self):
        pass

    @memoize
    def children(self):
        pass


class CloseStartElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x02.

    This is the "close start element" token.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(CloseStartElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseStartElementNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "CloseStartElementNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token())
        )

    def flags(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        pass

    def children(self):
        pass

    def verify(self):
        pass


class CloseEmptyElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x03.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(CloseEmptyElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseEmptyElementNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "CloseEmptyElementNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x03)
        )

    def flags(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        pass

    def children(self):
        pass


class CloseElementNode(BXmlNode):
    """
    The binary XML node for the system token 0x04.

    This is the "close element" token.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(CloseElementNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)

    def __repr__(self):
        return "CloseElementNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "CloseElementNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token())
        )

    def flags(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        pass

    def children(self):
        pass

    def verify(self):
        pass


def get_variant_value(buf, offset, chunk, parent, type_, length=None):
    """
    @return A VariantType subclass instance found in the given
      buffer and offset.
    """
    pass


class ValueNode(BXmlNode):
    """
    The binary XML node for the system token 0x05.

    This is the "value" token.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(ValueNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "type")

    def __repr__(self):
        return "ValueNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "ValueNode(offset={}, length={}, token={}, value={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token()), self.value().string()
        )

    def flags(self):
        pass

    def value(self):
        pass

    def tag_length(self):
        pass

    def children(self):
        pass

    def verify(self):
        pass


class AttributeNode(BXmlNode):
    """
    The binary XML node for the system token 0x06.

    This is the "attribute" token.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(AttributeNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")

        self._name_string_length = 0
        if self.string_offset() > self.offset() - self._chunk._offset:
            new_string = self._chunk.add_string(self.string_offset(), parent=self)
            self._name_string_length += new_string.length()

    def __repr__(self):
        return "AttributeNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "AttributeNode(offset={}, length={}, token={}, name={}, value={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token()), self.attribute_name(), self.attribute_value()
        )

    def flags(self):
        pass

    def attribute_name(self):
        """
        @return A NameNode instance that contains the attribute name.
        """
        pass

    def attribute_value(self):
        """
        @return A BXmlNode instance that is one of (ValueNode,
          ConditionalSubstitutionNode, NormalSubstitutionNode).
        """
        pass

    def tag_length(self):
        pass

    def verify(self):
        pass

    @memoize
    def children(self):
        pass


class CDataSectionNode(BXmlNode):
    """
    The binary XML node for the system token 0x07.

    This is the "CDATA section" system token.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(CDataSectionNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "string_length")
        self.declare_field("wstring", "cdata", length=self.string_length() - 2)

    def __repr__(self):
        return "CDataSectionNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "CDataSectionNode(offset={}, length={}, token={})".format(hex(self.offset()), hex(self.length()), 0x07)

    def flags(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        pass

    def children(self):
        pass

    def verify(self):
        pass


class CharacterReferenceNode(BXmlNode):
    """
    The binary XML node for the system token 0x08.

    This is an character reference node.  That is, something that represents
      a non-XML character, eg. & --> &#x0038;.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(CharacterReferenceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "entity")
        self._tag_length = 3

    def __repr__(self):
        return "CharacterReferenceNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "CharacterReferenceNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x08)
        )

    def entity_reference(self):
        pass

    def flags(self):
        pass

    def tag_length(self):
        pass

    def children(self):
        pass


class EntityReferenceNode(BXmlNode):
    """
    The binary XML node for the system token 0x09.

    This is an entity reference node.  That is, something that represents
      a non-XML character, eg. & --> &amp;.

    TODO(wb): this is untested.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(EntityReferenceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")
        self._tag_length = 5

        if self.string_offset() > self.offset() - self._chunk.offset():
            new_string = self._chunk.add_string(self.string_offset(), parent=self)
            self._tag_length += new_string.length()

    def __repr__(self):
        return "EntityReferenceNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "EntityReferenceNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x09)
        )

    def entity_reference(self):
        pass

    def flags(self):
        pass

    def tag_length(self):
        pass

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        pass


class ProcessingInstructionTargetNode(BXmlNode):
    """
    The binary XML node for the system token 0x0A.

    TODO(wb): untested.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(ProcessingInstructionTargetNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("dword", "string_offset")
        self._tag_length = 5

        if self.string_offset() > self.offset() - self._chunk.offset():
            new_string = self._chunk.add_string(self.string_offset(), parent=self)
            self._tag_length += new_string.length()

    def __repr__(self):
        return "ProcessingInstructionTargetNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "ProcessingInstructionTargetNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x0A)
        )

    def processing_instruction_target(self):
        pass

    def flags(self):
        pass

    def tag_length(self):
        pass

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        pass


class ProcessingInstructionDataNode(BXmlNode):
    """
    The binary XML node for the system token 0x0B.

    TODO(wb): untested.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(ProcessingInstructionDataNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "string_length")
        self._tag_length = 3 + (2 * self.string_length())

        if self.string_length() > 0:
            self._string = self.unpack_wstring(0x3, self.string_length())
        else:
            self._string = ""

    def __repr__(self):
        return "ProcessingInstructionDataNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "ProcessingInstructionDataNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x0B)
        )

    def flags(self):
        pass

    def string(self):
        pass

    def tag_length(self):
        pass

    def children(self):
        # TODO(wb): it may be possible for this element to have children.
        pass


class TemplateInstanceNode(BXmlNode):
    """
    The binary XML node for the system token 0x0C.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(TemplateInstanceNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "unknown0")
        self.declare_field("dword", "template_id")
        self.declare_field("dword", "template_offset")

        self._data_length = 0

        if self.is_resident_template():
            new_template = self._chunk.add_template(self.template_offset(), parent=self)
            self._data_length += new_template.length()

    def __repr__(self):
        return "TemplateInstanceNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "TemplateInstanceNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x0C)
        )

    def flags(self):
        pass

    def is_resident_template(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        pass

    def template(self):
        pass

    def children(self):
        pass

    @memoize
    def find_end_of_stream(self):
        pass


class NormalSubstitutionNode(BXmlNode):
    """
    The binary XML node for the system token 0x0D.

    This is a "normal substitution" token.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(NormalSubstitutionNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "index")
        self.declare_field("byte", "type")

    def __repr__(self):
        return "NormalSubstitutionNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "NormalSubstitutionNode(offset={}, length={}, token={}, index={}, type={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token()), self.index(), self.type()
        )

    def flags(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        pass

    def children(self):
        pass

    def verify(self):
        pass


class ConditionalSubstitutionNode(BXmlNode):
    """
    The binary XML node for the system token 0x0E.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(ConditionalSubstitutionNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("word", "index")
        self.declare_field("byte", "type")

    def __repr__(self):
        return "ConditionalSubstitutionNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "ConditionalSubstitutionNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(0x0E)
        )

    def should_suppress(self, substitutions):
        pass

    def flags(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        pass

    def children(self):
        pass

    def verify(self):
        pass


class StreamStartNode(BXmlNode):
    """
    The binary XML node for the system token 0x0F.

    This is the "start of stream" token.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(StreamStartNode, self).__init__(buf, offset, chunk, parent)
        self.declare_field("byte", "token", 0x0)
        self.declare_field("byte", "unknown0")
        self.declare_field("word", "unknown1")

    def __repr__(self):
        return "StreamStartNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "StreamStartNode(offset={}, length={}, token={})".format(
            hex(self.offset()), hex(self.length()), hex(self.token())
        )

    def verify(self):
        pass

    def flags(self):
        pass

    def tag_length(self):
        pass

    def length(self):
        pass

    def children(self):
        pass


class RootNode(BXmlNode):
    """
    The binary XML node for the Root node.
    """

    def __init__(self, buf, offset, chunk, parent):
        super(RootNode, self).__init__(buf, offset, chunk, parent)

    def __repr__(self):
        return "RootNode(buf={!r}, offset={!r}, chunk={!r}, parent={!r})".format(
            self._buf, self.offset(), self._chunk, self._parent
        )

    def __str__(self):
        return "RootNode(offset={}, length={})".format(hex(self.offset()), hex(self.length()))

    def tag_length(self):
        pass

    @memoize
    def children(self):
        """
        @return The template instances which make up this node.
        """
        pass

    def tag_and_children_length(self):
        """
        @return The length of the tag of this element, and the children.
          This does not take into account the substitutions that may be
          at the end of this element.
        """
        pass

    def template_instance(self):
        """
        parse the template instance node.
        this is used to compute the location of the template definition structure.

        Returns:
          TemplateInstanceNode: the template instance.
        """
        pass

    def template(self):
        """
        parse the template referenced by this root node.
        note, this template structure is not guaranteed to be located within the root node's boundaries.

        Returns:
          TemplateNode: the template.
        """
        pass

    @memoize
    def substitutions(self):
        """
        @return A list of VariantTypeNode subclass instances that
          contain the substitutions for this root node.
        """
        pass

    @memoize
    def length(self):
        pass


class VariantTypeNode(BXmlNode):
    """ """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(VariantTypeNode, self).__init__(buf, offset, chunk, parent)
        self._length = length

    def __repr__(self):
        return "{}(buf={!r}, offset={}, chunk={!r})".format(
            self.__class__.__name__, self._buf, hex(self.offset()), self._chunk
        )

    def __str__(self):
        return "{}(offset={}, length={}, string={})".format(
            self.__class__.__name__, hex(self.offset()), hex(self.length()), self.string()
        )

    def tag_length(self):
        raise NotImplementedError("tag_length not implemented for {!r}".format(self))

    def length(self):
        pass

    def children(self):
        pass

    def string(self):
        raise NotImplementedError("string not implemented for {!r}".format(self))


# but satisfies the contract of VariantTypeNode, BXmlNode, but not Block
class NullTypeNode(object):
    """
    Variant type 0x00.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(NullTypeNode, self).__init__()
        self._offset = offset
        self._length = length

    def __str__(self):
        return "NullTypeNode"

    def string(self):
        pass

    def length(self):
        pass

    def tag_length(self):
        pass

    def children(self):
        pass

    def offset(self):
        pass


class WstringTypeNode(VariantTypeNode):
    """
    Variant ttype 0x01.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(WstringTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        if self._length is None:
            self.declare_field("word", "string_length", 0x0)
            self.declare_field("wstring", "_string", length=(self.string_length()))
        else:
            self.declare_field("wstring", "_string", 0x0, length=(self._length // 2))

    def tag_length(self):
        pass

    def string(self):
        pass


class StringTypeNode(VariantTypeNode):
    """
    Variant type 0x02.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(StringTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        if self._length is None:
            self.declare_field("word", "string_length", 0x0)
            self.declare_field("string", "_string", length=(self.string_length()))
        else:
            self.declare_field("string", "_string", 0x0, length=self._length)

    def tag_length(self):
        pass

    def string(self):
        pass


class SignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x03.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedByteTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("int8", "byte", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class UnsignedByteTypeNode(VariantTypeNode):
    """
    Variant type 0x04.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedByteTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("byte", "byte", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class SignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x05.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedWordTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("int16", "word", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class UnsignedWordTypeNode(VariantTypeNode):
    """
    Variant type 0x06.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedWordTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("word", "word", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class SignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x07.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedDwordTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("int32", "dword", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class UnsignedDwordTypeNode(VariantTypeNode):
    """
    Variant type 0x08.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedDwordTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("dword", "dword", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class SignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x09.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SignedQwordTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("int64", "qword", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class UnsignedQwordTypeNode(VariantTypeNode):
    """
    Variant type 0x0A.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(UnsignedQwordTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("qword", "qword", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class FloatTypeNode(VariantTypeNode):
    """
    Variant type 0x0B.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(FloatTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("float", "float", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class DoubleTypeNode(VariantTypeNode):
    """
    Variant type 0x0C.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(DoubleTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("double", "double", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class BooleanTypeNode(VariantTypeNode):
    """
    Variant type 0x0D.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(BooleanTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("int32", "int32", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class BinaryTypeNode(VariantTypeNode):
    """
    Variant type 0x0E.

    String/XML representation is Base64 encoded.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(BinaryTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        if self._length is None:
            self.declare_field("dword", "size", 0x0)
            self.declare_field("binary", "binary", length=self.size())
        else:
            self.declare_field("binary", "binary", 0x0, length=self._length)

    def tag_length(self):
        pass

    def string(self):
        pass


class GuidTypeNode(VariantTypeNode):
    """
    Variant type 0x0F.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(GuidTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("guid", "guid", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class SizeTypeNode(VariantTypeNode):
    """
    Variant type 0x10.

    Note: Assuming sizeof(size_t) == 0x8.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SizeTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        if self._length == 0x4:
            self.declare_field("dword", "num", 0x0)
        elif self._length == 0x8:
            self.declare_field("qword", "num", 0x0)
        else:
            self.declare_field("qword", "num", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class FiletimeTypeNode(VariantTypeNode):
    """
    Variant type 0x11.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(FiletimeTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("filetime", "filetime", 0x0)

    def string(self):
        pass

    def tag_length(self):
        pass


class SystemtimeTypeNode(VariantTypeNode):
    """
    Variant type 0x12.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SystemtimeTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("systemtime", "systemtime", 0x0)

    def tag_length(self):
        pass

    def string(self):
        pass


class SIDTypeNode(VariantTypeNode):
    """
    Variant type 0x13.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(SIDTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("byte", "version", 0x0)
        self.declare_field("byte", "num_elements")
        self.declare_field("dword_be", "id_high")
        self.declare_field("word_be", "id_low")

    @memoize
    def elements(self):
        pass

    @memoize
    def id(self):
        pass

    def tag_length(self):
        pass

    def string(self):
        pass


class Hex32TypeNode(VariantTypeNode):
    """
    Variant type 0x14.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(Hex32TypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("binary", "hex", 0x0, length=0x4)

    def tag_length(self):
        pass

    def string(self):
        pass


class Hex64TypeNode(VariantTypeNode):
    """
    Variant type 0x15.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(Hex64TypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self.declare_field("binary", "hex", 0x0, length=0x8)

    def tag_length(self):
        pass

    def string(self):
        pass


class BXmlTypeNode(VariantTypeNode):
    """
    Variant type 0x21.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(BXmlTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        self._root = RootNode(buf, offset, chunk, self)

    def tag_length(self):
        pass

    def string(self):
        pass

    def root(self):
        pass


class WstringArrayTypeNode(VariantTypeNode):
    """
    Variant ttype 0x81.
    """

    def __init__(self, buf, offset, chunk, parent, length=None):
        super(WstringArrayTypeNode, self).__init__(buf, offset, chunk, parent, length=length)
        if self._length is None:
            self.declare_field("word", "binary_length", 0x0)
            self.declare_field("binary", "binary", length=(self.binary_length()))
        else:
            self.declare_field("binary", "binary", 0x0, length=(self._length))

    def tag_length(self):
        pass

    def string(self):
        pass


node_dispatch_table = [
    EndOfStreamNode,
    OpenStartElementNode,
    CloseStartElementNode,
    CloseEmptyElementNode,
    CloseElementNode,
    ValueNode,
    AttributeNode,
    CDataSectionNode,
    CharacterReferenceNode,
    EntityReferenceNode,
    ProcessingInstructionTargetNode,
    ProcessingInstructionDataNode,
    TemplateInstanceNode,
    NormalSubstitutionNode,
    ConditionalSubstitutionNode,
    StreamStartNode,
]

node_readable_tokens = [
    "End of Stream",
    "Open Start Element",
    "Close Start Element",
    "Close Empty Element",
    "Close Element",
    "Value",
    "Attribute",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "unknown",
    "TemplateInstanceNode",
    "Normal Substitution",
    "Conditional Substitution",
    "Start of Stream",
]
