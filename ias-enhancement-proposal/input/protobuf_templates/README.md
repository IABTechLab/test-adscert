#generate python protobuf scripts
#run from project root directory

protoc -I=input/protobuf_templates --python_out=./ input/protobuf_templates/schain.proto

protoc -I=input/protobuf_templates --python_out=./ input/protobuf_templates/anon_cert.proto