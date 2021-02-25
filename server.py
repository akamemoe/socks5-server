import socket
from struct import pack,unpack
import threading
import sys
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d - %(message)s',datefmt='%m-%d %H:%M:%S')

### reference:https://tools.ietf.org/html/rfc1928

# +----+-----+-------+------+----------+----------+
# |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
# +----+-----+-------+------+----------+----------+
# | 1  |  1  | X'00' |  1   | Variable |    2     |
# +----+-----+-------+------+----------+----------+

def recv_req(c):
    data = c.recv(4)
    assert len(data) == 4
    ver = int(data[0])
    assert ver == 0x05,"unsupported socks version"
    cmd = int(data[1])
    atyp = int(data[3])
    if atyp == 0x01:#IPv4
        target_ip = c.recv(4)
        target = socket.inet_ntoa(target_ip)
        logging.info('received request, target[IPv4] = {}'.format(target))
    elif atyp == 0x03:#domain
        ndomain = int(c.recv(1))
        domain = c.recv(ndomain).decode()
        target = socket.gethostbyname(domain)
        logging.info('received request, target[DOMAIN] = {}({})'.format(domain,target))
    elif atyp == 0x04:#IPv6
        target_ip6 = c.recv(16)
        logging.info('received request, target[IPv6] = unimplement')
        pass
    port = c.recv(2)
    port = unpack('>H',port)[0]
    if cmd != 0x01:
        logging.error('command not implement, cmd = {}'.format(cmd))
    return (target,port)


# +----+-----+-------+------+----------+----------+
# |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
# +----+-----+-------+------+----------+----------+
# | 1  |  1  | X'00' |  1   | Variable |    2     |
# +----+-----+-------+------+----------+----------+

def send_reply(c,addr,port,success=True):
    bnd = socket.inet_aton(addr) + pack('>H',port)
    a = 0x00 if success else 0x04
    data = bytes([0x05,a,0x00,0x01]) + bytes(bnd)
    c.sendall(data)


def stream_copy(src,dst):
    while True:
        try:
            buf = src.recv(20480)
            if not buf:
                return
            dst.sendall(buf)
        except BaseException as e:
            raise e


def stream_transfer(conn,another):
    t1 = threading.Thread(target=stream_copy,args=(conn,another))
    t2 = threading.Thread(target=stream_copy,args=(another,conn))
    t1.start()
    t2.start()


# +----+----------+----------+
# |VER | NMETHODS | METHODS  |
# +----+----------+----------+
# | 1  |    1     | 1 to 255 |
# +----+----------+----------+
# +----+--------+
# |VER | METHOD |
# +----+--------+
# | 1  |   1    |
# +----+--------+
# +----+------+----------+------+----------+
# |VER | ULEN | USERNAME | PLEN | PASSWORD |
# +----+------+----------+------+----------+
# | 1  |  1   | 1 to 255 |   1  | 1 to 255 |
# +----+------+----------+------+----------+
def negotiate(c,credentail=()):
    data = c.recv(2)
    assert len(data) == 2,"bad data"
    assert data[0] == 0x05,"bad data"
    nmethods = int(data[1])
    methods = c.recv(nmethods)
    # 0x00: NO AUTHENTICATION REQUIRED
    # 0x01: GSSAPI
    # 0x02: USERNAME/PASSWORD
    # 0x03: IANA ASSIGNED
    # 0x80-0xfe: RESERVED FOR PRIVATE METHODS
    # 0xff: NO ACCEPTABLE METHODS
    if credentail and len(credentail) == 2:
        c.sendall(bytes([0x05,0x02]))
        ver = int(c.recv(1)[0])
        ulen = int(c.recv(1)[0])
        username = c.recv(ulen).decode()
        plen = int(c.recv(1)[0])
        password = c.recv(plen).decode()
        if username == credentail[0] and password == credentail[1]:
            c.sendall(bytes([0x05,0x00]))
            return True
        else:
            c.sendall(bytes([0x05,0xff]))
            logging.error('authentication failed -> {}:{}'.format(username,password))
            return False
    else:
        c.sendall(bytes([0x05,0x00]))
        return True

def close_conn(*args):
    try:
        for c in args:
            c.close()
    except:
        pass

def serve(credentail=()):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host = ('0.0.0.0',13838)
    s.bind(host)
    s.listen()
    logging.info('listening on {}:{}'.format(*host))
    while True:
        try:
            conn,addr = s.accept()
            logging.info('accept a new connection, addr = {}'.format(addr))
            if not negotiate(conn,credentail):
                close_conn(conn)
                continue
            dst_addr,dst_port = recv_req(conn)
            another = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            another.connect((dst_addr,dst_port))
            send_reply(conn,dst_addr,dst_port)
            stream_transfer(conn,another)
        except socket.error as ex:
            logging.error('sokcet error:%s',ex)
            close_conn(conn,another)
        except BaseException as e:
            logging.error(e)
            close_conn(conn,another)
            sys.exit(1)

if __name__ == '__main__':
    serve(('thief','chief'))
