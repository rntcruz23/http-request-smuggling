# MIT License

# Copyright (c) 2020 Anshuman Pattnaik

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import time
import json
import os
from urllib.parse import urlparse
from .Constants import Constants

class Utils():
    def write_payload(self, fileName, payload):
        if not os.path.exists(os.path.dirname(fileName)):
            try:
                os.makedirs(os.path.dirname(fileName))
            except OSError as e:
                print(e)
        with open(fileName, "wb") as f:
            f.write(bytes(str(payload),'utf-8'))

    def url_parser(self, url):
        parser = {}
        try:
            u_parser = urlparse(url)
            
            port_temp = 80
            if u_parser.scheme == 'https':
                parser["ssl"] = True
                port_temp = 443
            if u_parser.scheme == 'http':
                parser["ssl"] = False

            parser["host"] = u_parser.hostname
            parser["port"] = u_parser.port if u_parser.port else port_temp
            
            path = u_parser.path
            query = '?'+u_parser.query if u_parser.query else ''
            fragment = '#'+u_parser.fragment if u_parser.fragment else ''
            uri_path = f'{path}{query}{fragment}'

            if len(path) > 0:
                parser["path"] = uri_path
            else:
                parser["path"] = '/'
            return json.dumps(parser)
        except:
            return Constants().invalid_target_url

    def read_target_list(self, file_name):
        try:
            with open(file_name) as urls_list:
                return [u.rstrip('\n') for u in urls_list]
        except FileNotFoundError as _:
            return Constants().file_not_found
