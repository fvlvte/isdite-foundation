#!/bin/bash
cd "$(dirname "$0")"

BUILD_DIR='./linux-x86'
TARGET='libIsditeFoundation.a'
INCLUDE_DIR='include/isdite/foundation'
LIB_DIR='lib'
HEADER_DIR='../source/h'
HEADER_DIR2='../source/c'
SOURCE_DIR='../source/c'

SOURCE_FILES=('app.c log.c tcp_server.c ierr.c qtls.c ext/aes.c mem.c util.c https_server.c rt/rtdb.c udp_server.c')

if [ ! -d $BUILD_DIR ]; then
  mkdir $BUILD_DIR;
fi

if [ ! -d $BUILD_DIR/$INCLUDE_DIR ]; then
  mkdir -p $BUILD_DIR/$INCLUDE_DIR;
fi

if [ ! -d $BUILD_DIR/$LIB_DIR ]; then
  mkdir $BUILD_DIR/$LIB_DIR;
fi

rm -R $BUILD_DIR/$INCLUDE_DIR/*
cp -R -f $HEADER_DIR/* $BUILD_DIR/$INCLUDE_DIR/

BUILD_STRING=''

for item in ${SOURCE_FILES[*]}
do
  BUILD_STRING+=$SOURCE_DIR/$item
  BUILD_STRING+=' '
done

clang -c -g -mtune=generic -D ISDITE_PLATFORM=0 \
-D ISDITE_PLATFORM_SPEC=0 -D ISDITE_DEBUG=1 -D ISDITE_NETSTAT -D ISDITE_WPP \
-D TLS_AMALGAMATION -D ISDITE_TLS -I $HEADER_DIR -I $HEADER_DIR2 $BUILD_STRING

ar -rcs $TARGET *.o
rm *.o
mv $TARGET $BUILD_DIR/$LIB_DIR/$TARGET
