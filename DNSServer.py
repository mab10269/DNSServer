import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdata
import dns.rrset
import socket
import threading
import signal
import os
import sys
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2  import PBKDF2HMAC
import base64

BIND_ADDR = '127.0.0.1'
PORT = 53

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key)


def encrypt_with_aes(input_string, password, salt):
    f = Fernet(generate_aes_key(password, salt))
    return f.encrypt(input_string.encode('utf-8'))


def decrypt_with_aes(encrypted_data, password, salt):
    f = Fernet(generate_aes_key(password, salt))
    return f.decrypt(encrypted_data).decode('utf-8')


salt = b'Tandon'
password = 'mab10269@NYU.edu'
input_string = 'AlwaysWatching'

encrypted_value = encrypt_with_aes(input_string, password, salt)
decrypted_value = decrypt_with_aes(encrypted_value, password, salt)


def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()


dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: 'ns.example.com.',
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },

    'safebank.com.': {
        dns.rdatatype.A: '192.168.1.102',
    },

    'google.com.': {
        dns.rdatatype.A: '192.168.1.103',
    },

    'legitsite.com.': {
        dns.rdatatype.A: '192.168.1.104',
    },

    'yahoo.com.': {
        dns.rdatatype.A: '192.168.1.105',
    },

    'nyu.edu.': {
        dns.rdatatype.A: '192.168.1.106',
        dns.rdatatype.TXT: ('"' + encrypted_value.decode('utf-8') + '"',),
        dns.rdatatype.MX: [(10, 'mxa-00256a01.gslb.pphosted.com.')],
        dns.rdatatype.AAAA: '2001:0db8:85a3:0000:0000:8a2e:0373:7312',
        dns.rdatatype.NS: 'ns1.nyu.edu.',
    },
}


def build_rdata_list(qtype, answer_data):
    rdata_list = []

    if qtype == dns.rdatatype.MX:
        for pref, server in answer_data:
            rdata_list.append(
                dns.rdata.from_text(
                    dns.rdataclass.IN, qtype, f'{pref} {server}'
                )
            )

    elif qtype == dns.rdatatype.SOA:
        mname, rname, serial, refresh, retry, expire, minimum = answer_data
        text = f'{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}'
        rdata_list.append(
            dns.rdata.from_text(dns.rdataclass.IN, qtype, text)
        )

    else:
        if isinstance(answer_data, str):
            answer_data = [answer_data]
        for item in answer_data:
            if qtype == dns.rdatatype.TXT and not item.startswith('"'):
                item = '"' + item + '"'
            rdata_list.append(
                dns.rdata.from_text(dns.rdataclass.IN, qtype, item)
            )

    return rdata_list


def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((BIND_ADDR, PORT))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)
            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = build_rdata_list(qtype, answer_data)

                rrset = dns.rrset.RRset(
                    question.name, dns.rdataclass.IN, qtype
                )
                for rdata in rdata_list:
                    rrset.add(rdata)
                response.answer.append(rrset)

            response.flags |= 1 << 10

            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)

        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

        except Exception as e:
            print('Error handling request:', e)


def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()

    run_dns_server()


if __name__ == '__main__':
    run_dns_server_user()
