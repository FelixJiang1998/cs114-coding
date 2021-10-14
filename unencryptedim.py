import select
import socket
import argparse
import sys
import signal
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC

global inputs, outputs, server


def server_exit_handle(signum, frame):
    global inputs, outputs, server
    inputs.remove(sys.stdin)
    for i in inputs:
        if i is server:
            continue
        else:
            # connection
            i.close()
    server.close()
    exit(0)


def encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    return ciphertext


def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext


def handle_k1_k2(k1, k2):
    e_k1 = SHA256.new(data=k1.encode("utf-8"))
    e_k2 = SHA256.new(data=k2.encode("utf-8"))
    return e_k1, e_k2


def run_server(listen_port, confkey, authkey):
    global inputs, outputs, server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.bind(("127.0.0.1", listen_port))
    server.listen(5)
    server.setblocking(False)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Server ready,listening on", listen_port)

    # readable list
    inputs = [server, sys.stdin]
    outputs = []

    # listen to signal from OS
    signal.signal(signal.SIGINT, server_exit_handle)

    while inputs:
        try:
            readable, writable, errors = select.select(inputs, outputs, inputs)
            for r in readable:
                if r is server:
                    # build connection
                    client_cnn, client_addr = r.accept()
                    # print("connected with", client_addr)
                    client_cnn.setblocking(False)
                    inputs.append(client_cnn)  # listen to this conn
                    outputs.append(client_cnn)  # if msg is from server, use this to broadcast
                elif r is sys.stdin:
                    # sent to client
                    message_broadcast = input()
                    if message_broadcast:
                        for w in outputs:
                            w.sendall(message_broadcast.encode("utf-8"))
                else:  # connection
                    # receive from client
                    data = r.recv(1024)
                    if data and len(data) > 0:
                        print(data.decode("utf-8"))
                        if r not in outputs:
                            outputs.append(r)
                    else:
                        # connection shut down
                        if r in outputs:
                            outputs.remove(r)
                        inputs.remove(r)
            # error handling
            for e in errors:
                inputs.remove(e)
                if e in outputs:
                    outputs.remove(e)
        except ValueError as e:
            for i in inputs:
                if i.fileno() == -1:
                    inputs.remove(i)
        except select.error as e:
            if e in outputs:
                inputs.remove(e)
            inputs.remove(e)
    server.close()


def client_exit_handle(signum, frame):
    global inputs
    inputs.remove(sys.stdin)
    for i in inputs:
        i.close()
    exit(0)


def run_client(hostname, port, k1, k2):
    global inputs
    print(hostname, port)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((hostname, port))
    client.setblocking(False)
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print("Server connected.")
    inputs = [client, sys.stdin, ]  # why other obj except socket cannot added in?

    # listen to signal
    signal.signal(signal.SIGINT, client_exit_handle)

    while inputs:
        try:
            readable, writable, errors = select.select(inputs, [], [])
            for r in readable:
                if r is client:
                    data = r.recv(1024)
                    if data and len(data) > 0:
                        data = data.decode("utf-8")
                        print(data)
                    else:
                        # the server shut down
                        client.close()
                        exit(0)
                else:  # sys.stdin
                    data = input()
                    # todo encrypt
                    p1 = iv = get_random_bytes(AES.block_size)
                    p2 = e_len_m = encrypt(len(data), k1, iv)
                    p3 = HMAC.new(k2, e_len_m, digestmod=SHA256).digest()
                    p4 = e_m = encrypt(data, k1, iv)
                    p5 = HMAC.new(k2, e_m, digestmod=SHA256).digest()
                    client.send(p1+p2+p3+p4+p5)
            # error handling
            for e in errors:
                inputs.remove(e)
        except ValueError as e:
            for i in inputs:
                if i.fileno() == -1:
                    inputs.remove(i)
        except select.error as e:
            if e in outputs:
                inputs.remove(e)
            inputs.remove(e)


if __name__ == '__main__':
    # read from command line
    parser = argparse.ArgumentParser(description='HW1_P1')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--s', help='launch as server', action="store_true")
    group.add_argument('--c', dest="dst", help='launch as client')

    parser.add_argument("--confkey", dest="confkey", help="confidentiality key", required=True)
    parser.add_argument("--authkey", dest="authkey", help="authenticity key", required=True)

    args = parser.parse_args()

    port = 9999  # fixed
    if args.s:
        run_server(port, args.confkey, args.authkey)
    else:
        run_client(args.dst, port, args.confkey, args.authkey)
