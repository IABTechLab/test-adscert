# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: anon_cert.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='anon_cert.proto',
  package='',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0f\x61non_cert.proto\"\xe0\x01\n\x0c\x41nonCertMain\x12*\n\tanon_cert\x18\x01 \x01(\x0b\x32\x17.AnonCertMain.Anon_cert\x1a\xa3\x01\n\tAnon_cert\x12\x16\n\x0e\x64\x65vice_pub_key\x18\x01 \x01(\x0c\x12\x11\n\tdevice_id\x18\x02 \x01(\t\x12\x17\n\x0fissuer_cert_url\x18\x03 \x01(\t\x12\x12\n\nexpiration\x18\x04 \x01(\x03\x12#\n\x16manufacturer_signature\x18\x05 \x01(\x0cH\x00\x88\x01\x01\x42\x19\n\x17_manufacturer_signatureb\x06proto3'
)




_ANONCERTMAIN_ANON_CERT = _descriptor.Descriptor(
  name='Anon_cert',
  full_name='AnonCertMain.Anon_cert',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='device_pub_key', full_name='AnonCertMain.Anon_cert.device_pub_key', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='device_id', full_name='AnonCertMain.Anon_cert.device_id', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='issuer_cert_url', full_name='AnonCertMain.Anon_cert.issuer_cert_url', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='expiration', full_name='AnonCertMain.Anon_cert.expiration', index=3,
      number=4, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='manufacturer_signature', full_name='AnonCertMain.Anon_cert.manufacturer_signature', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='_manufacturer_signature', full_name='AnonCertMain.Anon_cert._manufacturer_signature',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=81,
  serialized_end=244,
)

_ANONCERTMAIN = _descriptor.Descriptor(
  name='AnonCertMain',
  full_name='AnonCertMain',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='anon_cert', full_name='AnonCertMain.anon_cert', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_ANONCERTMAIN_ANON_CERT, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=20,
  serialized_end=244,
)

_ANONCERTMAIN_ANON_CERT.containing_type = _ANONCERTMAIN
_ANONCERTMAIN_ANON_CERT.oneofs_by_name['_manufacturer_signature'].fields.append(
  _ANONCERTMAIN_ANON_CERT.fields_by_name['manufacturer_signature'])
_ANONCERTMAIN_ANON_CERT.fields_by_name['manufacturer_signature'].containing_oneof = _ANONCERTMAIN_ANON_CERT.oneofs_by_name['_manufacturer_signature']
_ANONCERTMAIN.fields_by_name['anon_cert'].message_type = _ANONCERTMAIN_ANON_CERT
DESCRIPTOR.message_types_by_name['AnonCertMain'] = _ANONCERTMAIN
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

AnonCertMain = _reflection.GeneratedProtocolMessageType('AnonCertMain', (_message.Message,), {

  'Anon_cert' : _reflection.GeneratedProtocolMessageType('Anon_cert', (_message.Message,), {
    'DESCRIPTOR' : _ANONCERTMAIN_ANON_CERT,
    '__module__' : 'anon_cert_pb2'
    # @@protoc_insertion_point(class_scope:AnonCertMain.Anon_cert)
    })
  ,
  'DESCRIPTOR' : _ANONCERTMAIN,
  '__module__' : 'anon_cert_pb2'
  # @@protoc_insertion_point(class_scope:AnonCertMain)
  })
_sym_db.RegisterMessage(AnonCertMain)
_sym_db.RegisterMessage(AnonCertMain.Anon_cert)


# @@protoc_insertion_point(module_scope)
