import argparse
import json
import time
import os
import sys
# import threading
from lib.Utils import Utils
from lib.Constants import Constants
from lib.SocketConnection import SocketConnection

utils = Utils()
constants = Constants()

# Argument parser
parser = argparse.ArgumentParser(description='HTTP Request Smuggling vulnerability detection tool')
parser.add_argument("-u", "--url", help="set the target url")
parser.add_argument("-urls", "--urls", help="set list of target urls, i.e (urls.txt)")
parser.add_argument("-t", "--timeout", default=10, help="set socket timeout, default - 10")
parser.add_argument("-m", "--method", default="POST", help="set HTTP Methods, i.e (GET or POST), default - POST")
parser.add_argument("-r", "--retry", default=2, help="set the retry count to re-execute the payload, default - 2")
parser.add_argument("-o", "--output", dest="reports", default="reports", help="Set output folder")
parser.add_argument("-p", "--payloads", dest="payloads", default="payloads.json", help="Payloads file")
args = parser.parse_args()

def hrs_detection(connection, method, permute_type, content_length_key, te_key, te_value, smuggle_type, content_length, payload, timeout):
    host = connection.host
    port = connection.port
    path = connection.path

    headers = ''
    headers += '{} {} HTTP/1.1{}'.format(method, path, constants.crlf)
    headers += 'Host: {}{}'.format(host, constants.crlf)
    headers += '{} {}{}'.format(content_length_key,content_length, constants.crlf)
    headers += '{}{}{}'.format(te_key, te_value, constants.crlf)
    smuggle_body = headers + payload

    permute_type = "["+permute_type+"]"
    elapsed_time = "-"
        
    try:
        connection.connect(timeout)

        # Start
        start_time = time.time()
        connection.send_payload(smuggle_body)
        response = connection.receive_data().decode("utf-8")
        end_time = time.time()
        # End

        connection.close_connection()
        elapsed_time = str(round((end_time - start_time) % 60, 2))+"s"
        test = f"{host}{path}, {permute_type}, {smuggle_type}, {elapsed_time}"
        if time.time() - start_time >= args.timeout:
            with open(connection.reports, "rw+") as f:
                f.write(test)

            print(f"{test}, NOK")

    except Exception as e:
        print(e)
    
    # There is a delay of 1 second after executing each payload
    time.sleep(1)

if __name__ == "__main__":
    # If the python version less than 3.x then it will exit
    if sys.version_info < (3, 0):
        print(constants.python_version_error_msg)
        sys.exit(1)

    # Both (url/urls) options not allowed at the same time
    if args.urls and args.url:
        print(constants.invalid_url_options)
        sys.exit(1)

    target_urls = list()
    if args.urls:
        urls = utils.read_target_list(args.urls)
        
        if constants.file_not_found in urls:
            print(f"[{args.urls}] not found in your local directory")
            sys.exit(1)
        target_urls = urls
    
    if args.url:
        target_urls.append(args.url)

    method = args.method.upper()
    if method != "POST" and method != "GET":
        print(constants.invalid_method_type)
        sys.exit(1)

    # To detect the HRS it requires at least 1 retry count
    if args.retry == 0:
        print(constants.invalid_retry_count)
        sys.exit(1)

    data = []
    with open(args.payloads) as payloads:
        data = json.load(payloads)

    try:
        for url in target_urls:
            result = utils.url_parser(url)
            connection = SocketConnection(result, args.reports)
            try:
                # Try every permutation
                for permute in data[constants.permute]:
                    # Try every type (TECL, CLTE)
                    for d in data[constants.detection]:
                        # Based on the retry value it will re-execute the same payload again
                        for _ in range(args.retry):
                            transfer_encoding_obj = permute[constants.transfer_encoding]
                            hrs_detection(connection,
                                        method,
                                        permute[constants.type],
                                        permute[constants.content_length_key],
                                        transfer_encoding_obj[constants.te_key],
                                        transfer_encoding_obj[constants.te_value],
                                        d[constants.type],
                                        d[constants.content_length],
                                        d[constants.payload],
                                        args.timeout)
            except ValueError as _:
                print(result)
    except KeyboardInterrupt as e:
        print(e)