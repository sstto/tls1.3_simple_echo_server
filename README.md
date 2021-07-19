# tls-multi-echo-server
> Implement a TLS 1.2 multi echo server using openssl

# Compile
> gcc -o server echo_mpserv.c -lssl -lcrypto


> gcc -o client echo_client.c -lssl -lcrypto


# How to implement
> ./server port


> ./client ip port
