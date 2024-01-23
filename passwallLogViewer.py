import re
import datetime
import pytz
from flask import Flask, jsonify, send_from_directory
import threading
import time
import os

# 全局变量
CONNECTIONS = {}
LOCALSRC = {}
DNSRECORDS = {}
CONNECTION_TIMEOUT = 20  # 定义连接超时时间（单位秒）
EXTRA_TIME_AFTER_END = 10  # 连接结束后额外保留时间（单位秒）
LOG_FILE_PATH = '/var/etc/passwall/TCP.log'  # 代理程序日志文件路径

# 使用Flask建立一个简单的API服务器
app = Flask(__name__)

# 连接信息类
class ConnectionInfo:
    def __init__(self, connection_id, start_time, client_ip, local_src_key=None):
        self.connection_id = connection_id
        self.start_time = start_time
        self.end_time = None
        self.domain = None
        self.ip = None
        self.detour = None
        self.client_ip = client_ip
        self.exposed = False
        self.ended = False
        self.local_src_key = local_src_key
        self.is_dns = False
        
    def to_json(self):
        if self.exposed and not self.has_ended_long_ago() and not self.is_dns:  # 只有exposed且未结束超过5秒的连接才对外暴露
            current_time = datetime.datetime.now(pytz.utc)
            duration = (current_time - self.start_time).total_seconds()
            return {
                'connection_id': self.connection_id,
                'domain': self.domain,
                'ip': self.ip,
                'detour': self.detour,
                'client_ip': self.client_ip,
                'alive_time': duration,
                'ended': self.ended
            }
        return None
    
    def update_details(self, domain=None, ip=None, detour=None):
        self.domain = domain if domain else self.domain
        self.ip = ip if ip else self.ip
        self.detour = detour if detour else self.detour
        
    def end_connection(self):
        self.end_time = datetime.datetime.now(pytz.utc)
        self.ended = True
        
    def has_ended_long_ago(self):
        if self.end_time:
            return (datetime.datetime.now(pytz.utc) - self.end_time).total_seconds() > EXTRA_TIME_AFTER_END
        return False
    
# API端点，返回当前活动的所有连接
@app.route('/connections')
def get_active_connections():
    current_time = datetime.datetime.now(pytz.utc)
    active_connections = []
    for conn_id, conn_info in list(CONNECTIONS.items()):  # 使用list复制字典项，因为在迭代中可能会修改字典
        if conn_info.has_ended_long_ago() or (current_time - conn_info.start_time).total_seconds() > CONNECTION_TIMEOUT:
            del CONNECTIONS[conn_id]  # 超时或结束超过5秒的连接移除
            if conn_info.local_src_key:  # 使用存储的键来从 LOCALSRC 中移除对象
                LOCALSRC.pop(conn_info.local_src_key, None)
        else:
            connection_json = conn_info.to_json()
            if connection_json:
                active_connections.append(connection_json)
    return jsonify(active_connections)

# API 端点，返回 DNS 记录列表
@app.route('/dns_records')
def get_dns_records():
    return jsonify(DNSRECORDS)

@app.route('/status')
def status():
    return send_from_directory(os.getcwd(), 'index.html')

def log_monitor(log_file_path):
    log_file = open(log_file_path, 'r')
    log_file.seek(0, os.SEEK_END)

    try:
        while True:
            line = log_file.readline()
            if not line:
                time.sleep(0.1)
                continue
            handle_log_line(line)
    except KeyboardInterrupt:
        print("Log monitoring interrupted by the user.")
    finally:
        log_file.close()

def handle_log_line(line):
    # 匹配日期时间、日志级别、连接id和日志内容
    regex_pattern = r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(.*?)\] \[(\d+)\] (.*?): (.+)"
    match = re.match(regex_pattern, line)
    if not match:
        # 处理日志时间
        time_match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
        if time_match:
            log_time = datetime.datetime.strptime(time_match.group(1), "%Y/%m/%d %H:%M:%S").replace(tzinfo=pytz.utc)
        else:
            log_time = None
            
        # 检查是否为"accepted"类型的日志行
        accepted_match = re.match(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} (\d+\.\d+\.\d+\.\d+:\d+) accepted tcp:(\d+\.\d+\.\d+\.\d+:\d+)", line)
        if accepted_match:
            local_address, ip_port = accepted_match.groups()
            conn_info = LOCALSRC.get(local_address)
            if conn_info and log_time:
                conn_info.update_details(ip=ip_port)
            return
        elif "[Info] app/dns" in line:
            dns_match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[Info\] app/dns: (.*?) got answer: (.*?)\. Type(.*?) -> \[(.*?)\] (.+?)ms", line)
            if dns_match:
                log_time, dns_server, domain, record_type, records, duration = dns_match.groups()
                log_timestamp = datetime.datetime.strptime(log_time, "%Y/%m/%d %H:%M:%S").replace(tzinfo=pytz.utc).timestamp()
                DNSRECORDS[domain] = {
                    "dns_server": dns_server,
                    "record_type": record_type,
                    "records": records.split(),
                    "duration_ms": float(duration),
                    "timestamp": log_timestamp
                }
            return
        elif "[dns-in -> dns-out]" in line or "[Error] app/dns" in line or "[Info] proxy/dns" in line: # 忽略已知情况
            return
        else:
            # 对于不是"accepted"类型又无法识别的日志，打印DEBUG信息
            print(f"DEBUG: Unrecognized log line: {line}")
            return
    else:
        date_str, _level, connection_id, _component, content = match.groups()
        log_time = datetime.datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=pytz.utc)

    # 处理received request事件
    if 'received request for' in content:
        match = re.search(r"received request for (\d+\.\d+\.\d+\.\d+):(\d+)", content)
        if match:
            client_ip, client_port = match.groups()
            local_src_key = f"{client_ip}:{client_port}"
            CONNECTIONS[connection_id] = ConnectionInfo(connection_id, log_time, client_ip, local_src_key)
            LOCALSRC[local_src_key] = CONNECTIONS[connection_id]

    # 处理sniffed domain事件
    elif 'sniffed domain:' in content:
        domain = re.search(r"sniffed domain: (.+)", content).group(1)
        conn_info = CONNECTIONS.get(connection_id)
        if conn_info:
            conn_info.update_details(domain=domain)

    # 处理taking detour事件
    elif 'taking detour' in content:
        detour = re.search(r"taking detour \[(.*?)\]", content).group(1)
        conn_info = CONNECTIONS.get(connection_id)
        if conn_info:
            conn_info.update_details(detour=detour)

    # 处理dialing TCP到tcp事件，表示外部连接被建立
    elif 'dialing TCP to tcp:' in content:
        conn_info = CONNECTIONS.get(connection_id)
        if conn_info:
            conn_info.exposed = True  # 标记连接已暴露给外部API

    # 处理connection ends事件
    elif 'connection ends' in content:
        conn_info = CONNECTIONS.get(connection_id)
        if conn_info:
            conn_info.end_connection()
            
    elif "handling DNS traffic to" in line:
        conn_info = CONNECTIONS.get(connection_id)
        if conn_info:
            conn_info.is_dns = True

    else:
        # 如果日志不符合以上任何一种格式
        print(f"DEBUG: Unrecognized log content: {content}")

def main():
    log_thread = threading.Thread(target=log_monitor, args=(LOG_FILE_PATH,))
    log_thread.start()

    try:
        app.run(host='0.0.0.0', port=5032)
    except KeyboardInterrupt:
        print("API server stops.")
    finally:
        log_thread.join()

if __name__ == '__main__':
    main()
    
