# hw1p1.py

import argparse
import select
import socket
import sys
import signal


# define some globals
HOST = ''
PORT = 9999
SOCKET_LIST = []



def handler(signum,frame):
    """ handle a SIGINT (ctrl-C) keypress """
    for s in SOCKET_LIST:                 #close all sockets
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


def connect_to_host( dst ):
    """ connects to the host 'dst' """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect( (dst,PORT) )
        SOCKET_LIST.append(s)
        return s
    except socket.error:
        print( "Could not connect to %s." % dst )
        sys.exit(0)
    


def parse_command_line():
    """ parse the command-line """
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--c", dest="dst", help="destination address")
    parser.add_argument("-s", "--s", dest="server", action="store_true",
                    default=False, help="start server mode")

    options = parser.parse_args()
 
    if not options.dst and not options.server:
        parser.print_help()
        parser.error("must specify either server or client mode")

    return options


if __name__ == "__main__":

    options = parse_command_line()

    # catch when the user presses CTRL-C
    signal.signal(signal.SIGINT,handler)

    if options.server:
        s = wait_for_incoming_connection()
    elif options.dst:
        s = connect_to_host(options.dst)
    else:
        assert(False)                         # this shouldn't happen

    rlist = [ s, sys.stdin ]
    wlist = []
    xlist = []

    while True:
        (r, w, x) = select.select(rlist,wlist,xlist)
        if s in r:                            # there is data to read from network
            data = s.recv(1024)
            data = data.decode("utf-8")
            if data == "":                    # other side ended connection
                break
            sys.stdout.write(data)
            sys.stdout.flush()
            
        if sys.stdin in r:                    # there is data to read from stdin
            data = sys.stdin.readline()
            if data == "":                    # we closed STDIN
                break
            s.send(str.encode(data))

    """
            If we get here, then we've got an EOF in either stdin or our network.
            In either case, we iterate through our open sockets and close them.
    """
    for sock in SOCKET_LIST:
        sock.close()

    sys.exit(0)                           # all's well that ends well!
