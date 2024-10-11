import re
import requests
import time

def find_matching_text(filename, regex_pattern):
    matches=[]
    with open (filename, 'r') as f:
        for line in f:
            for match in re.findall(regex_pattern, line):
                matches.append(match)
    return matches

def get_request_ip(list):
    throttle = 60
    for element in list:
        r = requests.get('https://freeipapi.com/api/json/'+ element)
        print(f"Response content for {element} is:", r.content)
        throttle-=1
        if throttle<3 and (list.index(element) != len(list) -1): ##forego throttle if it's the last element
            for i in range (60,0,-1):
                print (f"You've hit the throttle limit. Resuming execution in: {i} seconds")
                time.sleep(1)
                if i==1:
                    throttle=60

class filterIP:
    def __init__(self, ip_list):
        self.ip_list=ip_list
    
    def removePrivateIP(self):
        regex_pattern = r"^(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.1[6-9]\.\d{1,3}\.\d{1,3})|(172\.2[0-9]\.\d{1,3}\.\d{1,3})|(172\.3[0-1]\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})$"
        filtered_list = [ip for ip in self.ip_list if not re.match(regex_pattern, ip)]
        return filtered_list


if __name__ == '__main__':
    filename = "list.csv"
    regex_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    
    matches = find_matching_text(filename, regex_pattern)
    filtered_ip = filterIP(matches)
    filtered_list = filtered_ip.removePrivateIP()
    print ("Results:", filtered_list)