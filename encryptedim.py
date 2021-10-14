# hw1p1.py

import argparse

import select
import socket
import sys
import signal
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC

# define some globals
HOST = ''
PORT = 9999
SOCKET_LIST = []


def handler(signum, frame):
    """ handle a SIGINT (ctrl-C) keypress """
    for s in SOCKET_LIST:  # close all sockets
        s.close()
    sys.exit(0)


def wait_for_incoming_connection():
    """
    create a server socket and wait for incoming connection

    returns the server socket
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    SOCKET_LIST.append(s)
    SOCKET_LIST.append(conn)
    return conn


def connect_to_host(dst):
    """ connects to the host 'dst' """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((dst, PORT))
        SOCKET_LIST.append(s)
        return s
    except socket.error:
        print("Could not connect to %s." % dst)
        sys.exit(0)


def parse_command_line():
    """ parse the command-line """
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--c", dest="dst", help="destination address")
    group.add_argument("-s", "--s", dest="server", action="store_true",
                       default=False, help="start server mode")

    parser.add_argument("--confkey", dest="confkey", help="confidentiality key", required=True)
    parser.add_argument("--authkey", dest="authkey", help="authenticity key", required=True)

    options = parser.parse_args()

    if not options.dst and not options.server:
        parser.print_help()
        parser.error("must specify either server or client mode")

    return options


def encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    return ciphertext


def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext
    # return cipher.decrypt(ciphertext)


def handle_k1_k2(k1, k2):
    e_k1 = SHA256.new(data=k1.encode("utf-8")).digest()
    e_k2 = SHA256.new(data=k2.encode("utf-8")).digest()
    return e_k1, e_k2


if __name__ == "__main__":

    options = parse_command_line()

    # catch when the user presses CTRL-C
    signal.signal(signal.SIGINT, handler)

    if options.server:
        s = wait_for_incoming_connection()
    elif options.dst:
        s = connect_to_host(options.dst)
    else:
        assert False  # this shouldn't happen

    rlist = [s, sys.stdin]
    wlist = []
    xlist = []

    # handle k1 and k2 with sha256
    k1, k2 = handle_k1_k2(options.confkey, options.authkey)

    while True:
        (r, w, x) = select.select(rlist, wlist, xlist)
        if s in r:  # there is data to read from network
            data = s.recv(1024 * 8)
            if data == "":  # other side ended connection
                break
            cursor = AES.block_size
            p1 = iv = data[:cursor]
            p2 = Ek_len_m = data[cursor:cursor + AES.block_size]
            cursor += AES.block_size
            len_m = int(decrypt(Ek_len_m, k1, iv).decode("utf-8"))

            p3 = send_auth = data[cursor:cursor + AES.block_size]
            cursor += AES.block_size

            cipher_length = AES.block_size * (len_m // AES.block_size + 1)

            p4 = cipher_text = data[cursor:cipher_length]
            cursor += cipher_length
            p5 = data[cursor:]

            try:
                hmac = HMAC.new(k2, Ek_len_m, digestmod=SHA256)
                hmac.verify(send_auth)
            except ValueError:
                print("ERROR: HMAC verification failed")
                break

            message = decrypt(cipher_text, k1, iv)
            try:
                hmac = HMAC.new(k2, message, digestmod=SHA256)
                hmac.verify(p5)
            except ValueError:
                print("ERROR: HMAC verification failed")
                break

            sys.stdout.write(message.decode("utf-8"))
            sys.stdout.flush()

        if sys.stdin in r:  # there is data to read from stdin
            # data = sys.stdin.readline()
            data = input()
            if data == "":  # we closed STDIN
                break

            p1 = iv = get_random_bytes(AES.block_size)
            p2 = e_len_m = encrypt(str(len(data)).encode(), k1, iv)
            p3 = HMAC.new(k2, e_len_m, digestmod=SHA256).digest()
            p4 = e_m = encrypt(data.encode("utf-8"), k1, iv)
            p5 = HMAC.new(k2, e_m, digestmod=SHA256).digest()
            s.send(p1)
            s.send(p2)
            s.send(p3)
            s.send(p4)
            s.send(p5)
        if s in x:
            break
    """
            If we get here, then we've got an EOF in either stdin or our network.
            In either case, we iterate through our open sockets and close them.
    """
    for sock in SOCKET_LIST:
        sock.close()

    sys.exit(0)  # all's well that ends well!
