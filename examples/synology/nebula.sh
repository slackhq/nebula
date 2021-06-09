#!/bin/bash

SCRIPT="PATH_TO_CONFIG" # example /volume1/nebula/config.yml
SUBNET="YOUR SUBNET IP" # example 10.1.0.0/24

PIDFILE="PATH_TO_PID" # example - /volume1/nebula/nebula.pid
LOGFILE="PATH_TO_LOG" # example - /volume1/nebula/nebula.log

status() {
  if [ -f $PIDFILE ]; then
    echo 'Service running' >&2
    return 1
  fi
}

start() {
  if [ -f $PIDFILE ] && kill -0 $(cat $PIDFILE); then
    echo 'Service already running' >&2
    return 1
  fi
  printf 'Starting nebula service...' >&2
  "$SCRIPT" &> "$LOGFILE" & echo $! > "$PIDFILE"
  sleep 5

  NEXT_WAIT_TIME=0
  until [ $NEXT_WAIT_TIME -eq 120 ] || [ ! -z "$(ifconfig | grep nebula1)" ]; do
    printf 'Failed\n'
    printf 'Starting nebula service...' >&2
    $SCRIPT &> "$LOGFILE" & echo $! > "$PIDFILE"
    sleep 5
    ((NEXT_WAIT_TIME++))
  done

  if [ "$NEXT_WAIT_TIME" -ge "120" ]; then
    printf "Failed\n"
    exit 1
  else
    printf "Success!\n"
  fi

  printf "Adding route..."
  route add -net "$SUBNET" dev nebula1
  sleep 5

  NEXT_WAIT_TIME=0
  until [ $NEXT_WAIT_TIME -eq 15 ] || [ ! -z "$(route | grep nebula1)" ]; do
    printf "Failed\n"
    printf "Adding route..."
    route add -net "$SUBNET" dev nebula1
    sleep 5
    ((NEXT_WAIT_TIME++))
  done

  if [ "$NEXT_WAIT_TIME" -ge "15" ]; then
    printf "Failed\n"
    exit 1
  else
    printf "Success!\n"
  fi
}

stop() {
  route del -net "$SUBNET" dev nebula1
  if [ ! -f "$PIDFILE" ] || ! kill -0 $(cat "$PIDFILE"); then
    echo 'Service not running' >&2
    return 1
  fi
  echo 'Stopping nebula service' >&2
  kill -15 $(cat "$PIDFILE") && rm -f "$PIDFILE"
  echo 'Service stopped' >&2
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  status)
    status
    ;;
  restart)
    stop
    start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
esac
