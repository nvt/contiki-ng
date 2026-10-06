#!/usr/bin/env bash

function ctrc_c( ) {
  kill_all_bg
  exit 1
}

function echo_run( )
{
    echo $@
    $@
}

function test_init( )
{
  # trap ctrl-c and call ctrl_c()
  trap ctrc_c INT
  # reset test success flag
  TEST_OK=1
  # remove prev logs and start new .testlog
  rm -f $BASENAME.*log
  echo "==== $BASENAME test results ====" > $BASENAME.testlog
  # Reset list of all log files
  LOGFILES=""
  # Reset list of all backgronud jobs' PID
  BG_PIDS=""
}

function register_logfile( )
{
  LOGFILES+=" $1"
}

function do_wrap_up( )
{
  kill_all_bg
  sleep 1

  if [ $TEST_OK -eq 0 ]; then
    for FILE in $LOGFILES; do
      echo "==== $FILE ====" ; cat $FILE;
    done
    echo ""
    echo "-- End of test"
    printf ">>> %-60s TEST FAIL\n" "$BASENAME" | tee -a $BASENAME.testlog;
    exit 1
  else
    echo ""
    echo "-- End of test"
    printf ">>> %-60s   TEST OK\n" "$BASENAME" | tee -a $BASENAME.testlog;
    exit 0
  fi
}

function register_last_bg_cmd( )
{
  BG_PIDS+=" $!"
}

# Every process below the given one, deepest first. sudo places more than one
# process between itself and the command on some systems, so the command is
# not always the direct child. $SUDO is set when the tree belongs to root,
# whose processes an ordinary user may not be allowed to see.
function descendants( )
{
    local CHILD
    for CHILD in $(${SUDO}pgrep -P $1); do
        descendants $CHILD
        echo $CHILD
    done
}

function kill_bg( )
{
    PID=$1
    CMD=$(ps -p $PID -o command=)
    SUDO=
    TOKILL=$PID
    SIGNAL=${2:-9}
    if [[ ${CMD:0:5} == "sudo " ]] ; then
        # The job runs as root, so the whole tree below sudo has to go with it.
        # Killing sudo alone leaves the command running and holding whatever it
        # opened, such as the tun device the next test needs.
        SUDO="sudo "
        TOKILL="$(descendants $PID) $PID"
    fi
    echo_run ${SUDO}kill -$SIGNAL $TOKILL
}

function kill_all_bg( ) {
  if [ ! -z "$INTERACTIVE_MODE" ] ; then
    read -p "Press enter to kill all jobs"
  fi
  echo "-- Killing background jobs"
  for PID in $BG_PIDS; do
    [[ ! -z "$PID" ]] && kill_bg $PID
  done
}

function report_start( )
{
  NAME=$1
  printf "* %-60s        " "$NAME ..." | tee -a $BASENAME.testlog;
}

function report_end_failure( )
{
  TIMEOUT=$1
  if [ -z $TIMEOUT ]; then
    printf "FAIL (%u seconds)\n" $SECONDS | tee -a $BASENAME.testlog;
  else
    printf "FAIL (%u seconds timeout)\n" $TIMEOUT | tee -a $BASENAME.testlog;
  fi
  TEST_OK=0
}

function report_end_success( )
{
  TIMEOUT=$1
  if [ -z $TIMEOUT ]; then
    printf "OK   (%u seconds)\n" $SECONDS | tee -a $BASENAME.testlog;
  else
    printf "OK   (%u/%u seconds)\n" $SECONDS $TIMEOUT | tee -a $BASENAME.testlog;
  fi
}

function report_skip( )
{
  report_start "$1"
  printf "SKIP\n" | tee -a $BASENAME.testlog;
}

function wait_log_assert( )
{
  NAME=$1
  STR=$2
  FILE=$3
  TIMEOUT=$4
  SECONDS=0
  if [ $TEST_OK -eq 0 ]; then
    # Test already failed, do not even read log file (may be from prev run)
    report_skip "$NAME"
    return
  fi
  # Wait until log file contains string. Polled, because a tail that follows
  # the file outlives the grep on systems other than Linux.
  report_start "$NAME"
  until grep -q "$STR" $FILE 2>/dev/null || [ $SECONDS -ge $TIMEOUT ]; do
    sleep 0.2
  done
  if grep -q "$STR" $FILE; then
    report_end_success $TIMEOUT
  else
    report_end_failure $TIMEOUT
  fi
}

function do_assert( )
{
  NAME=$1
  CMD=$2
  SECONDS=0
  # Wait until log file contains string
  report_start "$NAME"
  eval $CMD
  if [ $? -eq 0 ]; then
    report_end_success
  else
    report_end_failure
  fi
}

function assert( )
{
  if [ $TEST_OK -eq 0 ]; then
    # Test already failed, do not even read log file (may be from prev run)
    report_skip "$1"
    return
  else
    do_assert "$1" "$2" 1
  fi
}

function assert_noskip( )
{
  do_assert "$1" "$2" 0
}
