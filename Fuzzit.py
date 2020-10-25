#!/usr/bin/python
# coding: utf-8

import sys, os
import requests, simplejson

RHOST=""
WORDLIST=[]
RULES=[]
INJECTIONS = []
VERBOSE=" "
 
OUTPUT="stdout"
COOKIE=None
SSL=False
TYPE="get"


def help():
    print("Usage: Fuzzit.py [RHOST] [WORDLIST] [RULE_FILE]")
    print("RHOST Format: www.url.com/script.php?injection_point=*")
    print("-t, --type [get/post/cookie/status]")
    print("-c, --cookie [COOKIE]")
    print("--cookie-file [FILE]")    
    print("-o, --output [FILE]")
    print("-v, -vv")
        
    sys.exit()

def GetArgs():
    global RHOST
    global WORDLIST
    global TYPE
    global OUTPUT
    global RULES
    global VERBOSE
    
    for arg in sys.argv:
        if(arg == "-h" or arg == "--help"):
            help()

        elif(arg == "-v" or arg == "-vv"):
            VERBOSE=arg[1:]
            print("Verbosity: " + VERBOSE)
            sys.argv.remove(arg)
            
        elif(arg == "--type" or arg == "-t"):
            TYPE = sys.argv[sys.argv.index(arg) + 1]
            if(TYPE in ["post", "get", "status", "cookie"]):
                print("Request type: " + TYPE)
                sys.argv.pop(sys.argv.index(arg) + 1)
                sys.argv.remove(arg)
            else:
                print("Invalid request type... Quitting") #TODO: Add more request types
                help()
            
        elif(arg == "--output" or arg == "-o"): #TODO: enable file output
            output_dir = sys.argv[sys.argv.index(arg) + 1] 
            if(output_dir != "stdin"):
                print("Output file: " + FILENAME)
                OUTPUT = output_dir
                sys.argv.pop(sys.argv.index(arg) + 1)
                sys.argv.remove(arg)
            else: 
                print("No file selected... Quitting")
                help()
                
        elif(arg == "--cookie" or arg == "-c"):
            COOKIE = sys.argv[sys.argv.index(arg) + 1]
            sys.argv.pop(sys.argv.index(arg) + 1)
            sys.argv.remove(arg)
            
        elif(arg == "--cookie-file"): 
            cookie_dir = sys.argv[sys.argv.index(arg) + 1]
            if(os.exists(cookie_dir)):
                with open(cookie_dir, "r") as cookie:
                    COOKIE = cookie.read()                
            else:
                print("Cookie file doesn't exist... Quitting")
                sys.exit()
            sys.argv.pop(sys.argv.index(arg) + 1)
            sys.argv.remove(arg)
            

    if(len(sys.argv) == 4):
        RHOST = sys.argv[1]
        IsSSL(RHOST)

        with open(sys.argv[2], "r") as wordfile:
            for i in wordfile.readlines():
                WORDLIST.append(i)

        with open(sys.argv[3], "r") as rulefile:
            RULES = simplejson.loads(rulefile.read())
                          
    else:
        print("!!Argument Error!!")
        help()

def IsSSL(rhost): #TODO: ssl support
    global SSL
    
    if "https" in rhost: 
        SSL = True    
        print("SSL: Enabled")
    else:
        print("SSL: Disabled")

def IsRuleCase(injection, rules_list):
    if(TYPE=="status"):
        injection = "MatchStatusCode"
        
    for rule in rules_list:
        check = True 
        for base_match_case in rule["base"]:
            if base_match_case not in injection:
                check = False
        if check == True:
            return rule

    return None

def CheckPageOutput(rule_args, response):
    try:
        page = requests.get(rule_args[0], params=injection, cookies=cookie,
                            allow_redirects=True, timeout=5)

        page.raise_for_status()
        for string in rule_args[1:]:
            if string not in page.content:
                return False
        return True

    except HTTPError:
        print("ERROR: Could not find output page...")
        return False
        
def CheckOutput(rule_args, response):
    for string in rule_args:
        if string not in response.content:
           return False
    return True

def MatchStatusCode(rule_args, response):
    for code in rule_args:
        if(response.status_code == code):
            return True

    return False

def LookupRule(rule, response):
    check_functions = { "MatchStringOutput": CheckOutput,
                        "MatchStringPage": CheckPageOutput,
                        "MatchStatusCode" : MatchStatusCode
                       }
    
    rule_type = rule["type"]
    rule_args = rule[rule_type]
    
    return check_functions[rule_type](rule_args, response)

def CheckIfInjectable(response, injections): 
    rule_checks = []

    for injection in injections.items():
        rule_type = IsRuleCase(injection, RULES)
        if(rule_type != None and rule_type not in rule_checks):
            rule_checks.append(rule_type)

    for rule in rule_checks:
        if(not LookupRule(rule, response)):
            return False
            
    return True

def RequestGet(rhost, injection, cookie):
    try:
        response = requests.get(rhost, params=injection, cookies=cookie,
                                allow_redirects=True, timeout=5)
    except:
        print("!!GET ERROR!!") 
        sys.exit()
        
    if(response != None):
        #print("Requested: " + response.url)
        #print(injection)
        #print("[Status: " + str(response.status_code) + " ]")
        #print("[Returned Cookies: " + str(response.cookies) + " ]") 
        #print(response.content)

        return response
            
    else:
        print("error...")
        return None 
     
def RequestPost(rhost, injection, cookie):
    try:
        response = requests.post(rhost, data=injection, cookies=cookie,
                             allow_redirects=True, timeout=5)
    except:
        print("!!POST ERROR!!")
        sys.exit()        

    if(response != None):
        #print("Requested: " + response.url)
        #print(injection)
        #print("[Status: " + str(response.status_code) + "]") 
        #print("[Returned Cookies: " + str(response.cookies) + " ]") 
        #print(response.content)
            
        return response
        
    else:
        print("error...")
        return None
         
def Scan(url, requests, cookie): #TODO: Enable ssl
    if(TYPE == "get"):
        for injection in requests:
            response = RequestGet(url, injection, cookie)
            if (response != None and CheckIfInjectable(response, injection)):
                PrintInfo(response, injection, True)
            else:
                PrintInfo(response, injection, False)

            response.cookies.clear()
                            
    elif(TYPE == "post"):
        for injection in requests:
            response = RequestPost(url, injection, cookie)
            if (response != None and CheckIfInjectable(response, injection)): 
                PrintInfo(response, injection, True)
            else:
                PrintInfo(response, injection, False)
                
            response.cookies.clear()

    elif(TYPE == "cookie"):
        for cookie_injection in cookies:
            response = RequestGet(url, requests, cookie_injection)
            if(response != None and CheckIfInjectable(response, injection)):
                PrintInfo(response, cookie_injection, True)
            else:
                PrintInfo(response, cookie_injection, False)

            reponse.cookies.clear()

    elif(TYPE == "status"):
        for url_case in url:
            response = RequestGet(url_case, requests, cookie)
            if(response != None and CheckIfInjectable(response, url_case)):
                PrintInfo(response, url_case, True)
            else:
                PrintInfo(response, url_case, False)

            response.cookies.clear()

def PrintInfo(response, injection, injectable):
    if(injectable == True):
        print("POSITIVE: " + str(injection))
    else:
        print("NEGATIVE: " + str(injection))

    if(VERBOSE[0] == "v"):
        print(" ┣ Request URL: " + str(response.url))
        print(" ┣ Status Code: " + str(response.status_code)+" "+str(response.reason)) 
        print(" ┣ Headers: \n " + str(response.headers)+"\n ┃")
        print(" ┗ Returned Cookies: " + str(response.cookies)+"\n") 
        if(VERBOSE == "vv"):
            print("======= RESPONSE =======")
            print(response.content)
            print("========================\n")
            
def GetURL(rhost):
    url = []
    request = []
    i = 0

    while(rhost[i] != "?" and i < len(rhost)):
        url.append(rhost[i])
        i += 1
    url_result = "".join(url)

    while(i < len(rhost)):
        request.append(rhost[i])
        i += 1
    request_result = "".join(request)
    
    if(url_result[0:7] == "http://" or url_result[0:8] == "https://"):
        return url_result, request_result
    else:
        if(SSL): return "https://" + url_result, request_result
        else: return "http://" + url_result, request_result
        
def GetInjectionPoints(input):
    injection_points = []
    non_injection_points = {}

    for i in range(len(input) - 1):
        if(input[i] == "=" and input[i+1] == "*"):
            injection_points.append(GetPointName(input, i))
            print("Injection point: " + GetPointName(input, i) + "=*") 
            
        elif(input[i] == "=" and input[i+1] != "*"):
            print("Non-Injection point: " + GetPointName(input, i))
            non_injection_points[GetPointName(input, i)] = GetPointValue(input, i)

        elif(input[i] != "=" and input[i+1] == "*" and TYPE == "check"):
            #print("Injection index: " + str(i))
            injection_points.append(str(i))
               
    
    return injection_points, non_injection_points

def GetPointValue(rhost, index):
    i = 1
    ch = []
    
    while(index+i < len(rhost) and rhost[index+i] not in ["&", " ", "\n"]): 
        ch.append(rhost[index+i])
        i += 1
    
    return "".join(ch) 
        
def GetPointName(rhost, index):
    i = 1
    ch = []
    
    while(rhost[index-i] not in ["?", "&", " ", "\n"]):
        ch.insert(0,rhost[index-i])
        i += 1

    return "".join(ch)

def MakeURLInjectionValues(injection_points, url):
    global INJECTIONS

    for line in WORDLIST:
        offset = 0    
        for index in injection_points:
            url.pop(index)
            url.insert(index+offset, line)
            offset += len(line) -1

            INJECTIONS.append("".join(url))
        
def MakeInjectionValues(injection_points, prev_index, prev_dict):
    global INJECTIONS

    try:
        if(prev_index >= len(injection_points)):
            print(prev_dict)
            INJECTIONS.append(prev_dict.copy())
            
            return 
        else:
            for line in WORDLIST:
                cur_dict = prev_dict.copy()
                cur_dict[injection_points[prev_index]] = line[:-1]
                MakeInjectionValues(injection_points, prev_index+1, cur_dict)

            return
    except:
        print("!!ERROR!!" + str(sys.exc_info()[0]))
        sys.exit()

def main():
    print("Fuzzer by iwakura1ain...\n")
    GetArgs()

    if(TYPE in ["get", "post"]):
        url = GetURL(RHOST)[0]
        injection_points, non_injections = GetInjectionPoints(RHOST)

        print("\nGenerating injections...")
        MakeInjectionValues(injection_points, 0, non_injections)

        print("\nScanning RHOST....")
        Scan(url, INJECTIONS, COOKIE)

    elif(TYPE in ["cookie"]):
        url, request = GetURL(RHOST)
        injection_points, non_injections = GetInjectionPoints(COOKIE)
        request_dict = GetInjectionPoints(request)[1]

        print("\nGenerating injections...")
        MakeInjectionValues(injection_points, 0, non_injections)

        print("Scanning RHOST....")
        Scan(url, request_dict, INJECTIONS )

    elif(TYPE in ["status"]):
        url, request = GetURL(RHOST)
        injection_points = GetInjectionPoints(url)[0]
        request_dict = GetInjectionPoints(request)

        print("\nGenerating injections...")
        MakeURLInjectionValues(injection_points, list(url))

        print("\nScanning RHOST....")
        Scan(INJECTIONS, request_dict, COOKIE)
        
    
main()




                
