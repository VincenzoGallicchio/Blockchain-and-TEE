from socket import socket, AF_INET, SOCK_STREAM
from ssl import SSLContext, PROTOCOL_TLS_SERVER
import urllib.request

ip = '127.0.0.1'
port = 8443
context = SSLContext(PROTOCOL_TLS_SERVER)
context.load_cert_chain('cert.pem', 'key.pem')


with socket(AF_INET, SOCK_STREAM) as server:
    server.bind((ip, port))
    server.listen(1)
    with context.wrap_socket(server, server_side=True) as tls:
        while True:
            connection, address = tls.accept()
            print(f'Connected by {address}')
            data = connection.recv(1024)
            print(f'Client Says: {data}')
            contents = urllib.request.urlopen("https://maker.ifttt.com/trigger/blockchain_op_requested/with/key/p7m2V3PuMaDV6zlb9iamUGX60kU9ImFvjSFTc44AlbO?value1="+data.decode('utf8').encode('latin1').decode('utf8')).read()
            connection.sendall(b"OK")
