#!/usr/bin/python
# coding: utf-8

import sys, os
import requests, simplejson

#Input:
RHOST=""
WORDLIST=[]
RULES=[]
INJECTIONS = []

#Options: 
VERBOSE=" "
HEADERS=None
COOKIE=None
OUTPUT=None
SSL=False
TYPE="get"


def GetArgs():
    global RHOST
    global WORDLIST
    global TYPE
    global OUTPUT
    global RULES
    global VERBOSE

    offset = 0
    for index in range(1, len(sys.argv)):
        arg = sys.argv[index+offset]
    
        if(arg == "-h" or arg == "--help"):
            help()

        elif(arg == "-v" or arg == "-vv"):
            VERBOSE=arg[1:]
            print("Verbosity: " + VERBOSE)
            sys.argv.remove(arg)
            offset -= 1

        elif(arg == "--headers" or arg == "-h"):
            HEADERS = sys.argv[index+offset+1]
            print("Headers: " + HEADERS)
            sys.argv.remove(HEADERS)
            sys.argv.remove(arg)
            offset -= 2
            
        elif(arg == "--type" or arg == "-t"):
            TYPE = sys.argv[index+offset+1]
            if(TYPE in ["post", "get", "status", "cookie"]):
                print("TYPE: " + TYPE)
                sys.argv.remove(TYPE)
                sys.argv.remove(arg)
                offset -= 2
            else:
                print("Wrong type...Quitting") #TODO: Add more request types
                help()
      
        elif(arg == "--output" or arg == "-o"): #TODO: enable file output
            OUTPUT = sys.argv[index+offset+1]
            print("Output: " + OUTPUT)
            sys.argv.remove(OUTPUT)
            sys.argv.remove(arg)
            offset -= 2
           
        elif(arg == "--cookie" or arg == "-c"):
            COOKIE = sys.argv[index+offset+1]
            print("COOKIES: " + COOKIE)
            sys.argv.remove(COOKIE)
            sys.argv.remove(arg)
            offset -= 2
            
        elif(arg == "--cookie-file"): 
            cookie_dir = sys.argv[index+offset+1]
            if(os.exists(cookie_dir)):
                with open(cookie_dir, "r") as cookie:
                    COOKIE = cookie.read()
                    print("COOKIE: " + COOKIE)
            else:
                print("Cookie file doesn't exist... Quitting")
                sys.exit()
            sys.argv.remove(cookie_dir)
            sys.argv.remove(arg)
            offset -= 2 

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


def help():
    print("Usage: Fuzzit.py [RHOST] [WORDLIST] [RULE_FILE]")

    print("RHOST Format: www.url.com/script.php?injection_point=*")
    print("  - Mark injection points with a '*'.")
    print("  - Input values for non-injection points.")
    print("  - For status scans, mark a single '*' where WORDLIST will be appended")
    print("-t, --type [get/post/cookie/status]")
    print("  - get: Send a get request with values from WORDLIST.")
    print("  - post: Send a post request with values from WORDLIST.")
    print("  - cookie: Send a get request with cookie values from WORDLIST.")
    print("  - status: Check if a url from WORDLIST exists.")
    
    print("-c, --cookie [COOKIE]")
    print("  - Specify cookie.")    
    print("--cookie-file [FILE]")
    print("  - Specify cookie from file.")
    
    print("-o, --output [FILE]")
    print("  - Output to FILE")
    
    print("-v, -vv")
    print(" - v: Show NEGATIVE requests and headers.")
    print(" - vv: Show response page.")
    
    sys.exit()

def WriteResponse(response, injection, injectable, output):
    if(os.path.exists(output)):
        output_file = open(output, "a")
    else:
        output_file = open(output, "a+")
    
    if(injectable == True):
        output_file.write("POSITIVE: " + str(injection) + "\n")
    elif(injectable == False and VERBOSE[0] == "v"):
        output_file.write("NEGATIVE: " + str(injection) + "\n")

    if(VERBOSE[0] == "v"):
        output_file.write(" ┣ URL: " + str(response.url) + "\n")
        output_file.write(" ┣ Status Code: "+ str(response.status_code)+" "
                          +str(response.reason) + "\n") 
        output_file.write(" ┣ Headers: \n " + str(response.headers)+"\n ┃" + "\n")
        output_file.write(" ┗ Returned Cookies: " + str(response.cookies)+"\n\n" ) 
        if(VERBOSE == "vv"):
            output_file.write("======= RESPONSE =======\n")
            output_file.write(response.content)
            output_file.write("========================\n")

    output_file.close()

def PrintInjections(injections):
    print("Injection count: " + str(len(injections)))
    if(VERBOSE == "vv"):
        print(injections)
    
def PrintResponse(response, injection, injectable, output):
    if(OUTPUT != None):
        WriteResponse(response, injection, injectable, output)
        
    if(injectable == True):
        print("POSITIVE: " + str(injection))
    elif(injectable == False and VERBOSE[0] == "v"):
        print("NEGATIVE: " + str(injection))
        
    if(VERBOSE[0] == "v"):
        print(" ┣ URL: " + str(response.url))
        print(" ┣ Status Code: " + str(response.status_code)+" "+str(response.reason)) 
        print(" ┣ Headers: \n " + str(response.headers)+"\n ┃")
        print(" ┗ Returned Cookies: " + str(response.cookies)+"\n") 
        if(VERBOSE == "vv"):
            print("======= RESPONSE =======")
            print(response.content)
            print("========================\n")
       
def IsSSL(rhost): #TODO: ssl support
    global SSL
    
    if "https" in rhost: 
        SSL = True    
        print("SSL: Enabled")
    else:
        print("SSL: Disabled")

#Find the rule associated with the injection 
def IsRuleCase(injection, rules_list):
    if(TYPE=="status"): #Only applies the status scans
        injection = "MatchStatusCode"
        
    for rule in rules_list:
        check = True 
        for base_match_case in rule["base"]:
            if base_match_case not in injection: #BUG:can't tell whether "id" vs "id", ">"
                check = False
                
        if check == True:
            return rule

    return None

#Matches a string from another page
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

#Matches a string from the response
def CheckOutput(rule_args, response):
    for string in rule_args:
        if string not in response.text:
            return False
    return True

#Matches the status code of the respone
def MatchStatusCode(rule_args, response):
    for code in rule_args:
        if(response.status_code == code):
            return True

    return False

#Calls the rule-check associated with the rule
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
        rule_type = IsRuleCase(injection[1], RULES)
        if(rule_type != None and rule_type not in rule_checks):
            rule_checks.append(rule_type)

    if(len(rule_checks) == 0 ):
        return False
    
    for rule in rule_checks:
        if(not LookupRule(rule, response)):
            return False
            
    return True

def RequestGet(rhost, injection, cookie, headers):
    try:
        response = requests.get(rhost, params=injection, cookies=cookie,
                                allow_redirects=True, timeout=5)
    except:
        print("!!GET ERROR!!") 
        sys.exit()
        
    if(response != None):
        return response    
            
    else:
        print("error...")
        return None 
     
def RequestPost(rhost, injection, cookie, headers):
    try:
        response = requests.post(rhost, data=injection, cookies=cookie,
                             allow_redirects=True, timeout=5)
    except:
        print("!!POST ERROR!!")
        sys.exit()        

    if(response != None):            
        return response
        
    else:
        print("error...")
        return None
         
def Scan(url, requests, cookie, headers, output): #TODO: Enable ssl
    if(TYPE == "get"):
        for injection in requests:
            response = RequestGet(url, injection, cookie, headers)
            if (response != None and CheckIfInjectable(response, injection)):
                PrintResponse(response, injection, True, output)
            else:
                PrintResponse(response, injection, False, output)

            response.cookies.clear()
                            
    elif(TYPE == "post"):
        for injection in requests:
            response = RequestPost(url, injection, cookie, headers)
            if (response != None and CheckIfInjectable(response, injection)): 
                PrintResponse(response, injection, True, output)
            else:
                PrintResponse(response, injection, False, output)
                
            response.cookies.clear()

    elif(TYPE == "cookie"):
        for cookie_injection in cookies:
            response = RequestGet(url, requests, cookie_injection)
            if(response != None and CheckIfInjectable(response, injection)):
                PrintResponse(response, cookie_injection, True)
            else:
                PrintResponse(response, cookie_injection, False)

            reponse.cookies.clear()

    elif(TYPE == "status"):
        for url_case in url:
            response = RequestGet(url_case, requests, cookie)
            if(response != None and CheckIfInjectable(response, url_case)):
                PrintResponse(response, url_case, True)
            else:
                PrintResponse(response, url_case, False)

            response.cookies.clear()
        
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

#Returns a list of injection point indexes and a dictionary of non-injected values
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
            injection_points.append(str(i))
               
    
    return injection_points, non_injection_points

#Get the value of a non-injected value
def GetPointValue(rhost, index):
    i = 1
    ch = []
    
    while(index+i < len(rhost) and rhost[index+i] not in ["&", " ", "\n"]): 
        ch.append(rhost[index+i])
        i += 1
    
    return "".join(ch) 

#Get the name of a value        
def GetPointName(rhost, index):
    i = 1
    ch = []
    
    while(rhost[index-i] not in ["?", "&", " ", "\n"]):
        ch.insert(0,rhost[index-i])
        i += 1

    return "".join(ch)

#Map a line to an injection point in a url (for status type scans) 
def MakeURLInjectionValues(injection_points, url):
    global INJECTIONS

    for line in WORDLIST:
        offset = 0    
        for index in injection_points:
            url.pop(index)
            url.insert(index+offset, line)
            offset += len(line) -1

            INJECTIONS.append("".join(url))

#Make a dictionary of values to send using recursion
def MakeInjectionValues(injection_points, prev_index, prev_dict):
    global INJECTIONS

    try:
        if(prev_index >= len(injection_points)):
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
    print("Fuzzit Web Scanner v0.4.5 by iwakura1ain...")
    print("======== OPTIONS ========")
    GetArgs()
    

    if(TYPE in ["get", "post"]):
        url = GetURL(RHOST)[0]
        injection_points, non_injections = GetInjectionPoints(RHOST)

        print("\n======== Generating Injections ========")
        MakeInjectionValues(injection_points, 0, non_injections)
        PrintInjections(INJECTIONS)
        
        print("\n======== Scanning RHOST ========")
        Scan(url, INJECTIONS, COOKIE, HEADERS, OUTPUT)

    elif(TYPE in ["cookie"]):
        url, request = GetURL(RHOST)
        injection_points, non_injections = GetInjectionPoints(COOKIE)
        request_dict = GetInjectionPoints(request)[1]

        print("\n======== Generating Injections ========")
        MakeInjectionValues(injection_points, 0, non_injections)
        PrintInjections(INJECTIONS)
        
        print("\n======== Scanning RHOST ========")
        Scan(url, request_dict, INJECTIONS, HEADERS, OUTPUT)

    elif(TYPE in ["status"]):
        url, request = GetURL(RHOST)
        injection_points = GetInjectionPoints(url)[0]
        request_dict = GetInjectionPoints(request)

        print("\n======== Generating Injections ========")
        MakeURLInjectionValues(injection_points, list(url))
        PrintInjections(INJECTIONS)
        
        print("\n======== Scanning RHOST ========")
        Scan(INJECTIONS, request_dict, COOKIE, HEADERS, OUTPUT)
        

if __name__ == "__main__":
    main()




                
