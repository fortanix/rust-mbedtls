```
scripts/config.py set MBEDTLS_SSL_PROTO_TLS1_3
scripts/config.py set MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE
scripts/config.py set MBEDTLS_THREADING_PTHREAD
scripts/config.py set MBEDTLS_THREADING_C
mkdir -p build
cmake -S . -B ./build -DENABLE_PROGRAMS=ON -DENABLE_TESTING=OFF && cmake --build ./build
./build/programs/ssl/ssl_pthread_server
# in another shell
multithread_test_c.sh
```

