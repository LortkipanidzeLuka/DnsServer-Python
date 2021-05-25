import struct
import sys
from socket import *
from threading import Thread
from dns_tools import *
from pathlib import Path
from easyzone import easyzone
from RecursiveFetcher import *

TTL = 60


def get_zone_headers_value_list(request_headers, answer_count, authority_count, additional_count):
    msg_id = request_headers['id']
    is_response = 1
    opcode = request_headers['opcode']
    is_auth = 1
    truncated = 0
    recursion_desired = request_headers["recursion_desired"]
    recursion_available = 1
    z = 0
    rcode = 0
    n_questions = 1
    n_ans = answer_count
    n_ns = authority_count
    n_additional = additional_count
    return get_headers_values_list(msg_id, is_response, opcode, is_auth, truncated, recursion_desired,
                                   recursion_available, z, rcode, n_questions, n_ans, n_ns, n_additional)


def handle_zone_request(parsed_msg, domain_flattened, config_file_path):
    domain_name = parsed_msg.questions[0].domain_name
    query_type = parsed_msg.questions[0].query_type
    class_type = parsed_msg.questions[0].query_class
    zone = easyzone.zone_from_file(domain_flattened, config_file_path)
    rdata = zone.names[domain_flattened].records(get_query_type_by_int(query_type)).items

    answer = dns_answer(domain_name=domain_name, query_type=query_type, query_class=class_type, ttl=TTL, rdata=rdata,
                        reference="", exchange="")

    request_headers = parsed_msg.headers.headers_dict
    values = get_zone_headers_value_list(request_headers, len(rdata), 0, 0)
    response_headers = dns_headers(values)
    response = dns_message(headers=response_headers, answer=answer, questions=parsed_msg.questions)

    raw_response = response.get_raw_message()
    return raw_response


def handle_request(server_socket, request, client_addr, CONFIG, cache):
    parsed_msg = dns_message(message=request)
    request_type = parsed_msg.questions[0].query_type
    request_class = parsed_msg.questions[0].query_class
    domain_flattened = parsed_msg.questions[0].domain_name_flattened

    if (domain_flattened, request_type, request_class) in cache:
        return cache[(domain_flattened, request_type, request_class)]

    config_file_path = CONFIG + domain_flattened + "conf"
    my_file = Path(config_file_path)

    if my_file.exists():
        raw_response = handle_zone_request(parsed_msg, domain_flattened, config_file_path)
        cache[(domain_flattened, request_type, request_class)] = raw_response
        server_socket.sendto(raw_response, client_addr)

    else:
        rf = recursive_fetcher()
        raw_response = rf.fetch(request)
        cache[(domain_flattened, request_type, request_class)] = raw_response
        server_socket.sendto(raw_response, client_addr)


def run_dns_server(CONFIG, IP, PORT):
    server_socket = socket(AF_INET, SOCK_DGRAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind((IP, int(PORT)))
    cache = {}
    while True:
        request, client_addr = server_socket.recvfrom(128)
        tmp_thread = Thread(target=handle_request, args=(server_socket, request, client_addr, CONFIG, cache))
        tmp_thread.start()


# do not change!
if __name__ == '__main__':
    CONFIG = sys.argv[1]
    IP = sys.argv[2]
    PORT = sys.argv[3]
    run_dns_server(CONFIG, IP, PORT)
