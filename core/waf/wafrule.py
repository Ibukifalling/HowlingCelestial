import os
import json
from flask import request
import re
data=open('all.rules','r').read().split('\n')


def detect_rule(requests,rules):
    for rule in rules:
        if rule['action']=="str":
            target_pos=rule['detect_position'].split('|')
            for j in target_pos:
                if j.startwith("$HEADERS_VAR:"):
                    header_name=j.split(':')[1]
                    try:
                        if rule['rule'] in requests.headers[header_name]:
                            return rule['warn_msg']
                    except:
                        pass
                elif j.startwith("URL"):
                    if rule['rule'] in requests.url:
                        return rule['warn_msg']
                elif j.startwith("BODY"):
                    if rule['rule'] in requests.data:
                        return rule['warn_msg']
                elif j.startwith("ARGS"):
                    try:
                        if rule['rule'] in requests.args:
                            return rule['warn_msg']
                    except:
                        pass
        elif rule['action']=="rx":
            target_pos=rule['detect_position'].split('|')
            for j in target_pos:
                if j.startwith("$HEADERS_VAR:"):
                    header_name=j.split(':')[1]
                    try:
                        if re.match(rule['rule'],requests.headers[header_name]):
                            return rule['warn_msg']
                    except:
                        pass
                elif j.startwith("URL"):
                    if re.match(rule['rule'],requests.url):
                        return rule['warn_msg']
                elif j.startwith("BODY"):
                    if re.match(rule['rule'],requests.data):
                        return rule['warn_msg']
                elif j.startwith("ARGS"):
                    try:
                        if re.match(rule['rule'],requests.args):
                            return rule['warn_msg']
                    except:
                        pass


def parse_rules(data):
    rule_json= {}
    for i in data:
        if i.startswith("MainRule"):
            rule_id = -1
            id_match = re.search(r'id:(\d+)', i)
            msg_match = re.search(r'msg:(.*?)"', i)
            mz_match = re.search(r'mz:(.*?)"', i)
            str_match = re.search(r'"str:(.*?)"', i)
            rx_match = re.search(r'"rx:(.*?)"', i)

            if id_match:
                rule_id = id_match.group(1)
                # print(f"Extracted ID: {rule_id}")
            else:
                print("ID not found in the rule.")
                print(i)
                exit()
            rule_json[rule_id]={}
            if msg_match:
                rule_json[rule_id]['warn_msg'] = msg_match.group(1)
            else:
                print("rule_json[rule_id]['warn_msg'] not found in the rule.")
                print(i)
                exit()
            if mz_match:
                rule_json[rule_id]['detect_position'] = mz_match.group(1)
            else:
                print("rule_json[rule_id]['detect_position'] not found in the rule.")
                print(i)
                exit()
            if str_match:
                rule_json[rule_id]['rule'] = str_match.group(1)
                rule_json[rule_id]['action']="str"
            elif rx_match:
                rule_json[rule_id]['rule'] = rx_match.group(1)
                rule_json[rule_id]['action']="rx"
            else:
                print("rule_json[rule_id]['rule'] not found in the rule.")
                print(i)
                exit()
            

            # rule_a=i.split(' ')
            # rule_id=rule_a[1][3:]
            # rule_json[rule_id]={}
            # rule_json[rule_id]['warn_msg']=rule_a[5][5:]
            

            # rule_json[rule_id]['action']="str"
            # rule_json[rule_id]['rule']=rule_a[3][5:-1]
            # rule_json[rule_id]['detect_position']= rule_a[4][4:-1]
    return rule_json

if __name__ == '__main__':
    result=parse_rules(data)
    print(result)