#!/bin/bash

APP_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

APP_PATH="${APP_DIR}/anubi.py"
CONF_PATH="${APP_DIR}/conf_anubi.py"
JSON_PATH="${APP_DIR}/conf/json"
LOG_PATH="${APP_DIR}/log"
PATH_ANUBI_SIGNATURES="${APP_DIR}/../anubi-signatures"
PATH_VENV="${APP_DIR}/anubi_env/"
MANAGEMENT_HOST=$(cat ${CONF_PATH} | grep management_host | awk -F' = ' '{print $2}' | sed "s/\"//g")
MANAGEMENT_PORT=$(cat ${CONF_PATH} | grep management_port | awk -F' = ' '{print $2}' | sed "s/\"//g")

mkdir -p $LOG_PATH

check_json() {
  for file_json in $(ls ${JSON_PATH}/*.json); do
    cat $file_json | jq . > /dev/null
    if [ $? -ne 0 ]; then
      echo $file_json errato
    fi
  done
}

clean_logs() {
  rm -rf ${LOG_PATH}/anubi*.log
}

status() {
  echo "Anubi process status: "
  ps xa | grep anubi.py | grep -v grep
  echo -en "\tAnubi management socket status: "
  test_port=$(ss -antp | grep ":${MANAGEMENT_PORT}")
  if [ "${test_port}" != "" ]; then
    echo "up"
  else
    echo "down"	    
  fi
  echo "Anubi logs status: "
  ls -lht ${LOG_PATH}/anubi*.log
  echo ""
}

start() {
    check_anubi=$(ps xa | grep "python3" | grep "anubi.py" | grep -v grep)
    if [ "${check_anubi}" != "" ]; then
      echo "The service is already running."
      exit 1
    fi	
    echo "Check port ${MANAGEMENT_PORT}/TCP already opened.."
    check_porta=$(ss -anpt | grep ":${MANAGEMENT_PORT}")
    if [ "${check_porta}" != "" ]; then
      echo "Port ${MANAGEMENT_PORT} is already opened"
      exit 1
    fi
    if [ $? -ne 0 ]; then
      echo "KO"
      exit 1
    fi
    echo ""
    if [ "${1}" == "daemon" ]; then
      nohup $PATH_VENV/bin/python3 -u $APP_PATH --start-full >> ${LOG_PATH}/anubi_std.log 2>&1 &
      echo "Service started."
    else
      $PATH_VENV/bin/python3 -u $APP_PATH --start-full
    fi
}

stop() {
  ps xa | grep python3 | grep anubi.py | grep -v grep | grep -o "^[ 0-9]\+" | xargs kill -9 > /dev/null 2>&1
}

restart() {
  stop
  sleep 3
  start "daemon"
}

case "$1" in
  tail)
    if [ "$2" != "" ]; then
      if [ -f ${LOG_PATH}/anubi_${2}.log ]; then
        tail -n100 -f ${LOG_PATH}/anubi_${2}.log 
      else
        echo "${LOG_PATH}/anubi_${2}.log not existent"
      fi
    else
      echo "Log name missed"
    fi
  ;;
  check_json)
    check_json
  ;;
  clean_logs)
    clean_logs
  ;;
  start)
    start "daemon"
  ;;
  stop)
    stop
  ;;
  restart)
    restart
  ;;
  status)
    status
  ;;
  run)
    start "nodaemon"
  ;;
  *)
  echo "Usage: $0 {start|stop|restart|run|check_json|clean_logs|status|tail}"
esac
