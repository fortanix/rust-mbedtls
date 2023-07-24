#!/bin/bash

# Function to make curl requests until a non-zero return code is encountered
make_curl_requests() {
    local count=1
    while true; do
        curl -k --tlsv1.3 https://localhost:4433
        local ret_code=$?
        if [ $ret_code -ne 0 ]; then
            echo "Thread $1 encountered non-zero return code: $ret_code"
            echo "Total requests made by Thread $1: $count"
            exit $ret_code
        fi

        if [ $count -eq 100 ]; then
            echo "Thread $1 completed $count requests successfully."
            exit 0
        fi

        ((count++))
    done
}

# Run 5 threads in parallel
for (( thread=1; thread<=5; thread++ )); do
    make_curl_requests $thread &
done

# Wait for any background thread to finish
wait -n

# If any thread exited with a non-zero code, terminate other threads
exit_code=$?
echo "Thread $exit_code exited first with non-zero code. Terminating other threads."
kill 0




