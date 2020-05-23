import socket
import sys
import threading
import re

HOST = '127.0.0.1'
PORT = 2510
threads = []
CURR_DIRECTORY = 'D:/networking' # Place where files will be stored
HEADER_REGEX = "(\S+): (.*)";

def generate_headers(response_code):
  header = ''
  if response_code == 200:
    header += 'HTTP/1.1 200 OK\n'
  elif response_code == 404:
    header += 'HTTP/1.1 404 Not Found\n\n'
  elif response_code == 400:
    header += 'HTTP/1.1 400 Bad Request\n\n'
  header += 'Content-type: text/plain\n'
  header += 'Server: PMK-Server\n'
  header += 'Connection: close\n'
  return header

def get_full_path(resource_path):
  if (resource_path == '/'):
    return CURR_DIRECTORY + "/index.txt"
  return CURR_DIRECTORY + resource_path

def recvall(conn):
  BUFF_SIZE = 1024
  data = b''
  while True:
    part = conn.recv(BUFF_SIZE)
    data += part
    if len(part) < BUFF_SIZE:
      break
  return data

def parse_request(request):
  lines = list(map(lambda item: item.strip(), request.split("\n")))
  parsed_reqv = {}
  (method, path, version) = lines[0].split(' ')
  parsed_reqv['method'] = method
  parsed_reqv['path'] = path
  parsed_reqv['version'] = version
  parsed_reqv['headers'] = {}
  parsed_reqv['body'] = ''
  idx = -1
  for j in range(1, len(lines)):
    if not lines[j]:
      idx = j + 1
      break
    else:
      res = re.findall(HEADER_REGEX, lines[j])[0]
      parsed_reqv['headers'][res[0]] = res[1]
  if idx != -1:
    for j in range(idx, len(lines)):
      parsed_reqv['body'] += lines[j] + '\n'
  parsed_reqv['body'] = parsed_reqv['body'].strip()
  return parsed_reqv


def handle_request(path, headers, body, method):
  filepath = get_full_path(path)
  print("Full path: {}".format(filepath))
  response_header = ''
  response_data = b''

  try:
    if method == 'GET':
      f = open(filepath, 'rb')
      response_data = f.read()
      print(response_data)
      f.close()
      response_header = generate_headers(200)
    else:
      f = open(filepath, 'w')
      f.write(body)
      f.close()
      response_header = generate_headers(200)
      if method == 'POST': response_data = b'Successfully created resource'
      if method == 'PUT': response_data = b'Successuflly updated/created resource'
  except Exception as exc:
    if method == 'GET':
      response_header = generate_headers(404)
      response_data = b"404. File not found."
    else:
      response_header = generate_headers(400)
      if method == 'POST': response_data = b'Error occurred in handling POST request'
      if method == 'PUT': response_data = b'Error occurred in handling PUT request'
  response_header += 'Content-Length: {}\n'.format(len(response_data))
  response = response_header.encode()
  response += '\n'.encode() + response_data
  return response


def handle_connection(conn, addr):
    request_data = recvall(conn).decode()
    if not request_data: return
    parsed_reqv = parse_request(request_data)
    method = parsed_reqv['method']
    path = parsed_reqv['path']
    headers = parsed_reqv['headers']
    body = parsed_reqv['body']
    if method == 'GET':
      response = handle_request(path, headers, body, 'GET')
      conn.sendall(response)
      conn.close()
    elif method == 'POST':
      response = handle_request(path, headers, body, 'POST')
      conn.sendall(response)
      conn.close()
    elif method == 'PUT':
      response = handle_request(path, headers, body, 'PUT')
      conn.sendall(response)
      conn.close()
    else:
      conn.sendall(b'Bad request')
      conn.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.bind((HOST, PORT))
  s.listen()
  while True:
    conn, addr = s.accept()
    new_thread = threading.Thread(target=handle_connection, args=(conn,addr))
    threads.append(new_thread)
    new_thread.start()


