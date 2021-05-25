from struct import *
import ipaddress

MESSAGE_TYPE_REQUEST = 0
MESSAGE_TYPE_RESPONSE = 1

OPCODE_STANDARD_QUERY = 0

RCODE_NO_ERROR = 0
RCODE_FORMAT_ERROR = 1
RCODE_SERVER_FAILURE = 2
RCODE_NAME_ERROR = 3
RCODE_NOT_IMPLEMENTED = 4
RCODE_REFUSED = 5

QTYPE_A = 1
QTYPE_MX = 15
QTYPE_NS = 2
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_TXT = 16

STRUCT_1_BYTE = '>B'
STRUCT_2_BYTES = '>H'
STRUCT_4_BYTES = '>I'

HEADERS = ["id",
           "is_response",
           "opcode",
           "is_auth",
           "is_trunc",
           "recursion_desired",
           "recursion_available",
           "z",
           "rcode",
           "n_questions",
           "n_ans",
           "n_ns",
           "n_additional",
           ]

HEADER_LENGTHS = [16, 1, 4, 1, 1, 1, 1, 3, 4, 16, 16, 16, 16]


def get_query_type_by_int(x):
    query_int_string_dict = {QTYPE_A: 'A',
                             QTYPE_CNAME: 'CNAME',
                             QTYPE_NS: 'NS',
                             QTYPE_MX: 'MX',
                             QTYPE_AAAA: 'AAAA',
                             QTYPE_SOA: 'SOA',
                             QTYPE_TXT: 'TXT'
                             }

    return query_int_string_dict[x]


def get_binary_str_of_length(x, length):
    str_binary = bin(int(x))[2:]
    return str_binary.zfill(length)


def split_string(string, n_parts):
    return [string[i:i + n_parts] for i in range(0, len(string), n_parts)]


def get_headers_values_list(msg_id, is_resp, opcode, is_auth, is_trunc, rec_des, rec_av, z, rcode, n_questions, n_ans,
                            n_ns, n_additional):
    return [msg_id, is_resp, opcode, is_auth, is_trunc, rec_des, rec_av, z, rcode, n_questions, n_ans, n_ns,
            n_additional]


def get_remaining_domain_from_pointer(message, pointer):
    remaining_string_pointer = unpack_from(STRUCT_2_BYTES, message, pointer)[0]
    pointer += 2
    remaining_domain_parts = parse_domain(message, remaining_string_pointer & 0x3FFF)[0]
    return remaining_domain_parts, pointer


def parse_domain(message, current_pointer):
    domain_parts = []

    while True:

        length = unpack_from(STRUCT_1_BYTE, message, current_pointer)[0]

        if length == 0:
            break

        if length == 0xC0:
            remaining_parts, pointer = get_remaining_domain_from_pointer(message, current_pointer)
            return domain_parts + remaining_parts, pointer

        domain_parts.append(unpack_from(">%ds" % length, message, current_pointer + 1))
        current_pointer += length + 1

    return domain_parts, current_pointer + 1


def parse_question(message, current_pointer, questions_count):
    domain_list = []

    for i in range(questions_count):
        domain, current_pointer = parse_domain(message, current_pointer)
        query_type, query_class = unpack_from('>2H', message, current_pointer)
        question = dns_question(query_type=query_type, query_class=query_class, domain_name=domain)
        current_pointer += 4

        domain_list.append(question)

    return domain_list, current_pointer


def parse_dns_message(message):
    msg_id = unpack_from(STRUCT_2_BYTES, message, 0)[0]
    flags = unpack_from(STRUCT_2_BYTES, message, 2)[0]
    question_count = unpack_from(STRUCT_2_BYTES, message, 4)[0]
    answer_count = unpack_from(STRUCT_2_BYTES, message, 6)[0]
    name_server_count = unpack_from(STRUCT_2_BYTES, message, 8)[0]
    additional_count = unpack_from(STRUCT_2_BYTES, message, 10)[0]

    flags_string = get_binary_str_of_length(flags, 16)

    is_response = flags_string[0] != '0'
    opcode = 0
    aa = flags_string[5] != 0
    is_truncated = flags_string[6] != 0
    recursion_desired = flags_string[7] != 0
    recursion_available = flags_string[8] != 0
    z = 0
    rcode = 0

    current_pointer = 12

    questions, current_pointer = parse_question(message, current_pointer, question_count)

    values = get_headers_values_list(msg_id, is_response, opcode, aa, is_truncated, recursion_desired,
                                     recursion_available, z, rcode, question_count, answer_count, name_server_count,
                                     additional_count)
    headers = dns_headers(values)

    return headers, questions


def flatten_domain_name(domain_parts_list):
    full_domain = ""
    for part_domain in domain_parts_list:
        full_domain += part_domain[0].decode("UTF-8") + "."

    return full_domain


class dns_message:
    def __init__(self, message="", answer="", headers="", questions=""):

        if message != "":
            self.message = message
            headers, questions = parse_dns_message(message)
            self.headers = headers
            self.questions = questions
        else:
            self.headers = headers
            self.questions = questions
            self.answer = answer

    def get_raw_message(self):
        raw_headers = self.headers.get_raw_headers()
        raw_question = self.questions[0].get_raw_question()
        raw_answers = self.answer.get_raw_answers()

        return raw_headers + raw_question + raw_answers


class dns_headers:
    def __init__(self, value_list=[]):
        zip_iterator = zip(HEADERS, value_list)
        self.headers_dict = dict(zip_iterator)

    def get_raw_headers(self):
        bytes_string = ''
        for i in range(len(HEADERS)):
            bytes_string += get_binary_str_of_length(self.headers_dict[HEADERS[i]], HEADER_LENGTHS[i])
        split_bytes_string = split_string(bytes_string, 16)

        raw_headers = b''
        for current_byte_string in split_bytes_string:
            raw_headers += pack(STRUCT_2_BYTES, int(current_byte_string, 2))

        return raw_headers


def get_raw_domain_name(domain_parts_list):
    raw_domain_name = b''
    for domain_part in domain_parts_list:
        if type(domain_part) == tuple:
            domain_part = domain_part[0]
            domain_part = domain_part.decode('utf-8')
        raw_domain_name += pack(STRUCT_1_BYTE, len(domain_part))
        for char in domain_part.encode('utf-8'):
            raw_domain_name += pack(STRUCT_1_BYTE, char)

    raw_domain_name += pack(STRUCT_1_BYTE, 0)
    return raw_domain_name


class dns_question:
    def __init__(self, query_type, query_class, domain_name):
        self.query_type = query_type
        self.query_class = query_class
        self.domain_name = domain_name
        self.domain_name_flattened = flatten_domain_name(domain_name)

    def get_raw_question(self):
        raw_question = b''
        raw_question += get_raw_domain_name(self.domain_name)
        raw_question += pack(STRUCT_2_BYTES, self.query_type)
        raw_question += pack(STRUCT_2_BYTES, self.query_class)
        return raw_question


class dns_answer:
    def __init__(self, domain_name, query_type, query_class, ttl, rdata, reference, exchange):
        self.domain_name = domain_name
        self.query_type = query_type
        self.query_class = query_class
        self.ttl = ttl

        self.rdata = rdata
        self.reference = reference
        self.exchange = exchange

    def get_raw_answers(self):
        raw_answers = b''

        raw_answers += get_raw_domain_name(self.domain_name)

        raw_answers += pack(STRUCT_2_BYTES, self.query_type)
        raw_answers += pack(STRUCT_2_BYTES, self.query_class)
        raw_answers += pack(STRUCT_4_BYTES, self.ttl)
        return self.get_raw_rdata(raw_answers)

    def get_raw_rdata(self, raw_answers_headers):
        raw_rdata = b''
        for current_answer in self.rdata:

            if self.query_type == QTYPE_A:
                raw_rdata += raw_answers_headers
                raw_rdata += pack(STRUCT_2_BYTES, 4)
                current_answer_split = current_answer.split('.')
                for number in current_answer_split:
                    raw_rdata += pack(STRUCT_1_BYTE, int(number))

            elif self.query_type == QTYPE_MX:
                current_answer_split = current_answer[1].split('.')
                raw_rdata += raw_answers_headers
                rdata_length = 2 + len(current_answer[1]) + 1
                raw_rdata += pack(STRUCT_2_BYTES, rdata_length)
                raw_rdata += pack(STRUCT_2_BYTES, current_answer[0])
                raw_rdata += get_raw_domain_name(current_answer_split[:-1])

            elif self.query_type == QTYPE_NS:

                rdata_length = len(current_answer) + 1
                raw_rdata += raw_answers_headers
                raw_rdata += pack(STRUCT_2_BYTES, rdata_length)
                raw_rdata += get_raw_domain_name(current_answer.split('.')[:-1])

            elif self.query_type == QTYPE_TXT:
                raw_rdata += raw_answers_headers
                raw_rdata += pack(STRUCT_2_BYTES, len(self.rdata[0]) + 1)
                raw_rdata += pack(STRUCT_1_BYTE, len(self.rdata[0]))
                raw_rdata += pack('{}s'.format(len(self.rdata[0])), self.rdata[0].encode('utf-8'))

            elif self.query_type == QTYPE_SOA:
                raw_rdata += raw_answers_headers
                soa_parts = current_answer.split(" ")
                raw_rdata += pack(STRUCT_2_BYTES, len(soa_parts[0]) + len(soa_parts[1]) + 2 + 4 * 5)
                raw_rdata += get_raw_domain_name(soa_parts[0].split(".")[:-1])
                raw_rdata += get_raw_domain_name(soa_parts[1].split(".")[:-1])
                raw_rdata += pack(STRUCT_4_BYTES, int(soa_parts[2]))
                raw_rdata += pack(STRUCT_4_BYTES, int(soa_parts[3]))
                raw_rdata += pack(STRUCT_4_BYTES, int(soa_parts[4]))
                raw_rdata += pack(STRUCT_4_BYTES, int(soa_parts[5]))
                raw_rdata += pack(STRUCT_4_BYTES, int(soa_parts[6]))

            elif self.query_type == QTYPE_AAAA:
                raw_rdata += raw_answers_headers
                raw_rdata += pack(STRUCT_2_BYTES, 16)
                ip = ipaddress.ip_address(current_answer)
                raw_rdata += ip.packed

        return raw_rdata
