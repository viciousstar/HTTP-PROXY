#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
from urllib import parse
import threading
import logging
import select
import time
import configparser
from rule import what_rule


STATE_INTI = 0
STATE_EXCEPT = 1
STATE_FINISH = 2

class Connect(object):
    """docstring for Connect"""
    def __init__(self, type):
        super(Connect, self).__init__()
        self.type = type
        self.state = STATE_INTI

    def recv(self, backlog):
        try:
            data = self.conn.recv(backlog)
            if not data:
                self.state = STATE_FINISH
                return None
            logger.debug("recv %d data form %s" % (len(data), str(self.addr)))
            return data
        except Exception as e:
            self.state = STATE_EXCEPT
            logger.exception("%s when recv data form %s" % (e, str(self.addr)))
            return None

    def send(self, data):
        try:
            if isinstance(data, str):
                data = bytes(data, "utf-8")
            self.conn.sendall(data)
            logger.debug("send %d data to %s" % (len(data), str(self.addr)))
            return True
        except Exception as e:
            self.state = STATE_EXCEPT
            logger.exception("%s when send data to %s" % (e, str(self.addr)))
            return False

    def close(self):
        self.conn.close()

class Client(Connect):
    """docstring for Client"""
    def __init__(self, conn, addr):
        super(Client, self).__init__("client")
        self.conn = conn
        self.addr = addr

class Server(Connect):
    """docstring for Server"""
    def __init__(self):
        super(Server, self).__init__("server")
        self.conn = None
        self.addr = None

    def connect(self, addr):
        try:
            self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.conn.connect(addr)
            self.addr = addr
            logger.debug("Connection %s success" % str(addr))
            return True
        except socket.error as e:
            logger.error("Connection %s failed" % str(addr))
            return False


class Proxy(threading.Thread):
    """docstring for Proxy"""
    def __init__(self, client):
        super(Proxy, self).__init__()
        self.client = client
        self.client_buffer = b"" # store data recv from client
        self.server = None
        self.server_buffer = b"" # store data recv from server

    def _get_header(self):
        while True:
            i = self.client_buffer.find(b"\r\n\r\n")
            if i > 0:
                logger.debug("get header form %s" % (str(self.client.addr)))
                header, self.client_buffer = self.client_buffer.split(b"\r\n\r\n", 1)
                return str(header, "utf-8") + "\r\n\r\n"
            else:
                data = self.client.recv(4096)
                if data == None:
                    logger.error("can not get header form %s" % (str(self.client.addr)))
                    return None
                self.client_buffer += data

    def _parser_header(self, header):
        request_line = header.split('\r\n')[0].split(' ')
        method = request_line[0]
        full_path = request_line[1]
        version = request_line[2]
        (scm, netloc, path, params, query, fragment) \
            = parse.urlparse(full_path, 'http')
        i = netloc.find(':')
        if i >= 0:
            address = netloc[:i], int(netloc[i + 1:])
        else:
            address = netloc, 80
        if method == "CONNECT":
            address = (path.split(':')[0], int(path.split(':')[1]))
        return method, address, scm, netloc, path, params, query, fragment, version, full_path

    def _build_header(self, header, method, address, scm, netloc, path, params, query, fragment, version):
        # header.replace('Proxy-Connection', "Connection", 1).replace('keep-alive', 'close', 1)
        # if method == "GET" or method == "Post":
        #     path = parse.urlunparse(("", "", path, params, query, ""))
        #     header = " ".join([method, path, version]) + "\r\n" +\
        #     header.split('\r\n', 1)[-1]
        return header

    def _connect_server(self):
        header = self._get_header()
        if not header:
            return False
        method, address, scm, netloc, path, params, query, fragment, version, full_path \
         = self._parser_header(header)
        if what_rule(full_path) == "REJECT":
            logger.info("REJECT %s according to rules" % full_path)
            self.client.send("HTTP/1.1" + "Error" + " Fail\r\n\r\n")
            return False
        header = self._build_header(header, method, address, scm, netloc, path, params, query, fragment, version)
        logger.info("%s %s %s" % (method, address, path))
        self.server = Server()
        if self.server.connect(address):
            if method == "CONNECT":
                self.client.send('HTTP/1.1 200 Connection Established\r\n\r\n')
            else:
                self.server.send(bytes(header, "utf-8"))
            return True
        self.client.send("HTTP/1.1" + "Error" + " Fail\r\n\r\n")
        return False


    def run(self):
        if not self._connect_server():
            return
        while True:
            r, w, e = select.select((self.client.conn, self.server.conn), (), (), 1)
            if self.client.conn in r:
                data = self.client.recv(10240)
                if data:
                    self.client_buffer += data
                elif self.client.state != STATE_INTI:
                    break
            if self.server.conn in r:
                data = self.server.recv(10240)
                if data:
                    self.server_buffer += data
                elif self.server.state != STATE_INTI:
                    break
            if self.server_buffer:
                self.client.send(self.server_buffer)
                self.server_buffer = b""
            if self.client_buffer:
                self.server.send(self.client_buffer)
                self.client_buffer = b""
        logger.info("complete request from %s to %s" % (str(self.client.addr), str(self.server.addr)))
        self.client.close()
        self.server.close()

def main():
    host = config["SETTING"]["host"]
    port = config["SETTING"]["port"]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, int(port)))
    s.listen(500)
    print("Proxy is serving at %s" % port)
    while True:
        try:
            conn, addr = s.accept()
            client = Client(conn, addr)
            proxy = Proxy(client)
            proxy.daemon = True
            proxy.start()
        except KeyboardInterrupt:
            print("Bye...")
            break

if __name__ == '__main__':
    config = configparser.ConfigParser()
    config.read("config.conf")
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    main()
