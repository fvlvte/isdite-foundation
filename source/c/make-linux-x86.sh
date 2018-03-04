#!/bin/bash
cd "$(dirname "$0")"

BUILD_DIR='./linux-x86'
TARGET='ira'
HEADER_DIR='../source/h'
SOURCE_DIR='../source/c'
REMOTE_HEADER_DIR='../../isdite-foundation/build/linux-x86/include'
REMOTE_LIBS='../../isdite-foundation/build/linux-x86/lib/libIsditeFoundation.a'
SOURCE_FILES=('app.c')

if [ ! -d $BUILD_DIR ]; then
  mkdir $BUILD_DIR;
fi

BUILD_STRING=''

for item in ${SOURCE_FILES[*]}
do
  BUILD_STRING+=$SOURCE_DIR/$item
  BUILD_STRING+=' '
done

# BUILD DEPENDENCIES
./../../isdite-foundation/build/make-linux-x86.sh

gcc -o $BUILD_DIR/$LIB_DIR/$TARGET -g -lpthread -D ISDITE_PLATFORM=0 \
-D ISDITE_PLATFORM_SPEC=0 -D ISDITE_DEBUG=1 -I $REMOTE_HEADER_DIR \
-I $HEADER_DIR $BUILD_STRING $REMOTE_LIBS
