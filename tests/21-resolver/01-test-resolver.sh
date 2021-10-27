#!/bin/sh

TESTNAME=01-test-resolver
TEST_CODE_DIR=code-test-resolver
TARGET=test-resolver.native

make -C ${TEST_CODE_DIR} clean
make -C ${TEST_CODE_DIR} ${TARGET}
sudo ${TEST_CODE_DIR}/${TARGET} > ${TESTNAME}.log

if [ $? -eq 0 ]; then
    echo "${TESTNAME} TEST OK" > ${TESTNAME}.testlog
    make -C ${TEST_CODE_DIR} clean
    exit 0
else
    echo "${TESTNAME} TEST FAIL" > ${TESTNAME}.testlog
    exit 1
fi
