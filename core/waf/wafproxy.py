# '''
#  +-----------------------------+         +---------------------------------------------+         +--------------------------------+
#  |     My Laptop (Alice)       |         |            Intermediary Server (Bob)        |         |    Internal Server (Carol)     |
#  +-----------------------------+         +----------------------+----------------------+         +--------------------------------+
#  | $ ssh -p 1022 carol@1.2.3.4 |<------->|    IF 1: 1.2.3.4     |  IF 2: 192.168.1.1   |<------->|       IF 1: 192.168.1.2        |
#  | carol@1.2.3.4's password:   |         +----------------------+----------------------+         +--------------------------------+
#  | carol@hostname:~$ whoami    |         | $ python pf.py --listen-host 1.2.3.4 \      |         | 192.168.1.2:22(OpenSSH Server) |
#  | carol                       |         |                --listen-port 1022 \         |         +--------------------------------+
#  +-----------------------------+         |                --connect-host 192.168.1.2 \ |
#                                          |                --connect-port 22            |
#                                          +---------------------------------------------+
# '''

import socket
import random
import threading
import argparse
import logging
import json
import re
from urllib.parse import urlparse, parse_qs
from k8sUtils import service_port_mapping


format = '%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s: %(message)s'
logging.basicConfig(level=logging.INFO, format=format)


# rules = json.load(open("testrules.json","r"))
rules = json.load(open("allrules.json","r"))
forbidden_page = b"""HTTP/1.1 403 Forbidden
Content-Type: text/html
Content-Length: 191

<!DOCTYPE html>
<html>
<head>
    <title>403 Forbidden</title>
</head>
<body>
    <h1>403 Forbidden</h1>
    <p>You don't have permission to access this resource.</p>
</body>
</html>
"""



def parse_raw_http(raw_http):
    # 将bytes转换为字符串
    http_str = raw_http.decode('utf-8')

    # 使用正则表达式提取请求方法、路径和协议版本，或者状态码和协议版本
    if http_str.startswith("GET") or http_str.startswith("POST") or http_str.startswith("PUT") or http_str.startswith("DELETE"):
        request_line_pattern = re.compile(r'(?P<method>[A-Z]+) (?P<path>[^ ]+) HTTP/(?P<version>\d\.\d)')
        line_match = request_line_pattern.match(http_str)
    else:
        status_line_pattern = re.compile(r'HTTP/(?P<version>\d\.\d) (?P<status_code>\d+)')
        line_match = status_line_pattern.match(http_str)

    if not line_match:
        raise ValueError("Invalid HTTP format")

    # 提取头部和体
    headers_pattern = re.compile(r'(?P<header_name>.*?): (?P<header_value>.*?)\r\n')
    headers_match = headers_pattern.finditer(http_str, line_match.end())

    headers = {match.group('header_name'): match.group('header_value') for match in headers_match}

    # 提取体
    body_match = re.search(r'\r\n\r\n(.*)', http_str, re.DOTALL)
    body = body_match.group(1) if body_match else ''

    # 解析 Content-Type
    content_type = headers.get('Content-Type', '')

    # 解析路径中的参数（仅对请求有效）
    request_params = {}
    if http_str.startswith("GET") or http_str.startswith("POST") or http_str.startswith("PUT") or http_str.startswith("DELETE"):
        parsed_url = urlparse(line_match.group('path'))
        request_params = dict(parse_qs(parsed_url.query))

    # 根据 Content-Type 解析请求体
    if 'application/x-www-form-urlencoded' in content_type:
        # 解析表单数据
        body_params = dict(parse_qs(body))
    elif 'application/json' in content_type:
        # 解析 JSON 数据
        try:
            body_params = json.loads(body)
        except json.JSONDecodeError:
            body_params = {}
    else:
        # 其他情况，直接将 body 视为文本
        body_params = body

    return {
        "is_request": http_str.startswith("GET") or http_str.startswith("POST") or http_str.startswith("PUT") or http_str.startswith("DELETE"),
        "method": line_match.group('method') if http_str.startswith("GET") or http_str.startswith("POST") or http_str.startswith("PUT") or http_str.startswith("DELETE") else None,
        "path": line_match.group('path') if http_str.startswith("GET") or http_str.startswith("POST") or http_str.startswith("PUT") or http_str.startswith("DELETE") else None,
        "version": line_match.group('version'),
        "status_code": line_match.group('status_code') if not (http_str.startswith("GET") or http_str.startswith("POST") or http_str.startswith("PUT") or http_str.startswith("DELETE")) else None,
        "headers": headers,
        "params": request_params,
        "body": body_params,
    }



def detect_http_payload(http_payload, rules):
    detected_warnings = []
    for rule_id, rule_info in rules.items():
        action = rule_info.get("action", "str")
        rule = rule_info.get("rule", "")
        detect_position = rule_info.get("detect_position", "")
        warn_msg = rule_info.get("warn_msg", "")

        # 提取检测位置信息
        positions = detect_position.split("|")
        for position in positions:
            data_to_check = ""
            if position.startswith("$"):
                position_type, position_value = position.split(":", 1)
                # 根据检测位置信息提取相应的数据
                if position_type == "$HEADERS_VAR":
                    data_to_check = http_payload.get("headers", {}).get(position_value, "")
                elif position_type == "$BODY":
                    data_to_check = http_payload.get("body", "")
                else:
                    # 其他检测位置的处理，可以根据实际需求扩展
                    data_to_check = ""
            elif position == "URL":
                data_to_check = http_payload.get("path", "")
            elif position == "ARGS":
                data_to_check = http_payload.get("params", "")
                
            elif position == "BODY":
                data_to_check = http_payload.get("body", "")
            if type(data_to_check) == dict:
                data_to_check = json.dumps(data_to_check)
            # print(rule_id, rule_info, data_to_check)
            # 根据匹配方法进行匹配
            if action == "str":
                if rule in data_to_check :
                    detected_warnings.append(rule_id + ":" + warn_msg)
                    break
            elif action == "rx":
                # if rule_id == "50000004":
                #     print(rule_id, rule_info, data_to_check)
                #     print()
                if re.search(rule, data_to_check):
                    detected_warnings.append(rule_id + ":" + warn_msg)
                    break
        if detected_warnings:
            break
    return detected_warnings

def waf(buffer):
    try:
        parsed_request = parse_raw_http(buffer)
        print(parsed_request)
        if parsed_request["is_request"]:
            detect_result = detect_http_payload(parsed_request,rules)
            if detect_result:
                logging.warning(f"Detect warning: {detect_result}")
                return True
            else:
                return False
        else:
            return False
    except Exception as e:
        logging.error(repr(e))
        # print(e)
        return False


def handle(buffer, direction, src_address, src_port, dst_address, dst_port):
    '''
    intercept the data flows between local port and the target port
    '''
    if direction:
        logging.info(f"{src_address, src_port} -> {dst_address, dst_port} {len(buffer)} bytes")
    else:
        logging.info(f"{src_address, src_port} <- {dst_address, dst_port} {len(buffer)} bytes")
    return buffer


def transfer(src, dst, direction):
    src_address, src_port = src.getsockname()
    dst_address, dst_port = dst.getsockname()
    while True:
        try:
            buffer = src.recv(4096)
            if len(buffer) == 0:
                break
            if waf(buffer):
                if direction:
                    src.send(forbidden_page)
                    break
                else:
                    dst.send(forbidden_page)
                    break
            
            dst.send(handle(buffer, direction, src_address, src_port, dst_address, dst_port))
        except Exception as e:
            logging.error(repr(e))
            break
    logging.warning(f"Closing connect {src_address, src_port}! ")
    src.close()
    logging.warning(f"Closing connect {dst_address, dst_port}! ")
    dst.close()


def server(local_host, local_port, remote_host, remote_port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((local_host, local_port))
    server_socket.listen(0x40)
    logging.info(f"Server started {local_host, local_port}")
    logging.info(f"Connect to {local_host, local_port} to get the content of {remote_host, remote_port}")
    while True:
        src_socket, src_address = server_socket.accept()
        logging.info(f"[Establishing] {src_address} -> {local_host, local_port} -> ? -> {remote_host, remote_port}")
        try:
            dst_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dst_socket.connect((remote_host, remote_port))
            logging.info(f"[OK] {src_address} -> {local_host, local_port} -> {dst_socket.getsockname()} -> {remote_host, remote_port}")
            s = threading.Thread(target=transfer, args=(dst_socket, src_socket, False))
            r = threading.Thread(target=transfer, args=(src_socket, dst_socket, True))
            s.start()
            r.start()
        except Exception as e:
            logging.error(repr(e))

def k8s_server(local_host, remote_host):
    for service_name, port in service_port_mapping.items():
        local_port = find_available_port()
        remote_port = port
        threading.Thread(target=server, args=(local_host, local_port, remote_host, remote_port)).start()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-host", help="the host to listen", required=True)
    parser.add_argument("--connect-host", help="the target host to connect", required=True)
    args = parser.parse_args()
    if len(args.listen_host.split(".")) != 4 or len(args.connect_host.split(".")) != 4:
        print_help()
        return
    k8s_server(args.listen_host, args.connect_host)


def find_available_port():
    def is_port_available(port):
        # 检查端口是否可用
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(('localhost', port))
                return True
            except OSError:
                return False

    def get_random_port():
        # 获取一个随机端口号
        return random.randint(1024, 65535)  # 一般来说，非特权端口号范围为1024到65535

    while True:
        port = get_random_port()
        if is_port_available(port):
            return port

def print_help():
    print("python3 wafproxy.py --listen-host xxx --connect-host xxx")

if __name__ == "__main__":
    main()