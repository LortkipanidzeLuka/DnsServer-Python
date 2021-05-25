from socket import *
from dns_tools import *

ROOT_SERVER_IP = '192.112.36.4'
DNS_SERVER_PORT = 53


def get_domain(message, request):
    len_headers = len(message.headers.get_raw_headers())
    len_questions = len(message.questions[0].get_raw_question())
    domain = parse_domain(request, len_headers + len_questions + 12)[0]
    return flatten_domain_name(domain)


class recursive_fetcher:

    def __init__(self):
        self.root_dns_server = ROOT_SERVER_IP
        self.dns_port = DNS_SERVER_PORT

    def fetch(self, request):
        data = self.do_recursive_fetch((self.root_dns_server, self.dns_port), request)
        return data

    def do_recursive_fetch(self, addr, request):
        dns_server_socket = socket(AF_INET, SOCK_DGRAM)
        dns_server_socket.sendto(request, addr)
        response, addr = dns_server_socket.recvfrom(4096)
        message = dns_message(response)

        answer_count = message.headers.headers_dict["n_ans"]
        if answer_count == 0:
            domain = get_domain(message, response)
            return self.do_recursive_fetch((domain, DNS_SERVER_PORT), request)

        return response
