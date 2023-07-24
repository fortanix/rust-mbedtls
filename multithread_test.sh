#!/bin/bash

iteration=1

while true; do
  start_time=$(date +"%Y-%m-%d %H:%M:%S")
  echo "Iteration: $iteration | Starting test at $start_time"

  cargo test --features async-rt,tls13,debug --test hyper test_hyper_server_tls13_multithread
  exit_status=$?

  end_time=$(date +"%Y-%m-%d %H:%M:%S")
  echo "Iteration: $iteration | Finished test at $end_time"

  if [ $exit_status -ne 0 ]; then
    echo "Command failed with exit status $exit_status"
    break
  fi

  iteration=$((iteration + 1))
done
