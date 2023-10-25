import argparse
import json
import pprint
import random
import string
import re

parser = argparse.ArgumentParser()
parser.add_argument('--input', help='HAR to be sanitized', required=True)
parser.add_argument('--out', help='filename for sanitized HAR', required=True)


class ParseException(Exception):
    pass


def _randomize(s):
    chars = string.ascii_letters
    if "=" in s:
        ret_str=''
        for r in re.findall(r'(.+?)=(.+?)(;\s)', s):
            st = r[1]
            st = f'{st[0]}{"".join(random.choice(chars) for x in range(len(st) - 2))}{st[-1]}'
            return f'{ret_str}{r[0]}={st}{r[2]}'
    else:
        return f'{s[0]}{"".join(random.choice(chars) for x in range(len(s) - 2))}{s[-1]}'

class HAR():
    def __init__(self, file):
        self.file = file
        self.json = json.JSONDecoder()
        pass

    def _load(self):
        with open(self.file, encoding='utf-8') as json_data:
            self.json = json.load(json_data)

    def cleanup(self):
        try:
            self._load()
        except Exception as e1:
            raise ParseException(e1)
        for entry in self.json['log']['entries']:

            for header in entry['request']['headers']:
                try:
                    if header["name"] == "cookie":
                        header["value"] = _randomize(header["value"])
                except:
                    pass
            for cookie in entry["request"]["cookies"]:
                try:
                    cookie["value"] = _randomize(cookie["value"])
                except:
                    print("Error reading Cookie")
                    raise ParseException("Error reading Cookie")

            for response_header in entry["response"]["headers"]:
                try:
                    if response_header["name"] == "set-cookie":
                        response_header["value"] = _randomize(response_header["value"])
                except:
                    pass

    def save(self, file):
        try:
            with open(file, 'w') as json_out:
                json.dump(self.json, json_out)
            json_out.close()
        except Exception as e:
            print(f'Failed to save HAR file {file}: {e}')
        print(f'Sanitized HAR saved successfully to {file}')

    def debug(self):
        pprint.pprint(self.json)


if __name__ == '__main__':
    args = parser.parse_args()
    file = args.input
    export = args.out
    h = HAR(file)
    try:
        h.cleanup()
    except ParseException as e:
        print(f'Failed to parse HAR file {file}: {e}')
        raise e
    h.save(export)
