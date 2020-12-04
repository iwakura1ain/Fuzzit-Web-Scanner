#!/usr/bin/python
# coding: utf-8
import sys, time, threading, os
import requests, socket, simplejson

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


class InjectionCase:
    def __init__(self, injection_dict):
        self.injection = injection_dict

        self.rules = self.GetRuleChecks()
        self.rule_scans, self.rule_args = self.LookupRuleScan(self.rules)
        self.response = None

        if(self.rules == None):
            self.result = [False]
        else:
            self.result = [False] * len(self.rules)
        
            
    def IsRuleCase(self, injection):
        best_match_case = None
        best_match_count = 0

        if(TYPE=="status"): #Only applies to status scans
            injection = "MatchStatusCode"
        
        for rule in RULES:
            match_count = 0
            match = True 
            for base_match_case in rule["base"]:
                if base_match_case not in injection:
                    match = False
                    break
                else:
                    match_count += 1
                    
            if match == True and match_count > best_match_count:
                best_match_case =  rule
                best_match_count = match_count
                
        return best_match_case
    
    def GetRuleChecks(self): 
        rules = []
        
        for injection in self.injection.items():
            rule_type = self.IsRuleCase(injection[1])
            if(rule_type != None and rule_type not in rules):
                rules.append(rule_type)

        if(len(rules) == 0 ):
            return None
        else:
            return rules

    #Calls the rule-check associated with the rule
    def LookupRuleScan(self, rules):
        check_functions = { "MatchStringOutput": CheckOutput
                            #"MatchStringPage": CheckPageOutput,
                            #"MatchStatusCode" : MatchStatusCode,
                            #"ListenOnPort" : ListenOnPort
                           }
        
        if(rules == None):
            return None, None
        
        rule_scans = []
        rule_args = []
        for rule in rules:
            rule_type = rule["type"]
            rule_scans.append(check_functions[rule_type])
            rule_args.append(rule[rule_type])
            
        return rule_scans, rule_args
            
    def Scan(self, url, input, cookie, headers):
        scan_threads = []
        result = True
        
        if(self.rule_scans == None):
            print("ERROR: Could not find rule case for " + str(self.injection))
            self.result[0] = False

            return False
            
        if(TYPE == "get"):               
            for i in range(0,len(self.rules)):
                thread = threading.Thread(target=self.rule_scans[i], args=(self, i,))
                scan_threads.append(thread)
                thread.start()
                
            self.response = RequestGet(url, input, cookie, headers)
            
        elif(TYPE == "post"):               
            for i in range(0,len(self.rules)):
                thread = threading.Thread(target=self.rule_scans[i], args=(self, i,))
                scan_threads.append(thread)
                thread.start()
                
            self.response = RequestPost(url, input, cookie, headers)

        elif(TYPE == "cookie"):
            for i in range(0,len(self.rules)):
                thread = threading.Thread(target=self.rule_scans[i], args=(self, i,))
                scan_threads.append(thread)
                thread.start()

            self.response = RequestGet(url, input, cookie, headers)

        elif(TYPE == "status"):
            thread = threading.Thread(target=self.rule_scans[0], args=(self, i,))
            thread.start() #Do we really need to start a thread here?

            self.response = RequestGet(url, input, cookie, headers)
        
        for i in range(0, len(self.rules)):
            scan_threads[i].join()
            if(self.result[i] == False):
                result = False
                    
        return result
                    
    def PrintResponse(self):
        if(OUTPUT != None):
            self.WriteResponse(OUTPUT)
        
        if(False not in self.result):
            print("POSITIVE: " + str(self.injection))
        elif(VERBOSE[0] == "v"):
            print("NEGATIVE: " + str(self.injection))
        
        if(VERBOSE[0] == "v" and self.response != None):
            print(" ┣ URL: " + str(self.response.url))
            print(" ┣ Status Code: " + str(self.response.status_code)+" "+str(self.response.reason)) 
            print(" ┣ Headers: \n " + str(self.response.headers)+"\n ┃")
            print(" ┗ Returned Cookies: " + str(self.response.cookies)+"\n") 
            if(VERBOSE == "vv"):
                print("======= RESPONSE =======")
                print(self.response.content)
                print("========================\n")
                
    def WriteResponse(self, output_dir):
        with open(output_dir, "a") as output:    
            if(False not in self.result):
                output.write("POSITIVE: " + str(self.injection) + "\n")
            elif(VERBOSE[0] == "v"):
                output.write("NEGATIVE: " + str(self.injection) + "\n")

            if(VERBOSE[0] == "v"):
                output.write(" ┣ URL: " + str(self.response.url) + "\n")
                output.write(" ┣ Status Code: "+ str(self.response.status_code)+" "
                              +str(response.reason) + "\n") 
                output.write(" ┣ Headers: \n " + str(self.response.headers)+"\n ┃" + "\n")
                output.write(" ┗ Returned Cookies: " + str(self.response.cookies)+"\n\n" ) 
                if(VERBOSE == "vv"):
                    output.write("======= RESPONSE =======\n")
                    output.write(self.response.content)
                    output.write("========================\n")
                    
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
    
def PrintInjections(injections):
    print("Injection count: " + str(len(injections)))
    if(VERBOSE == "vv"):
        print(injections)
        
def IsSSL(rhost): #TODO: ssl support
    global SSL
    
    if "https" in rhost: 
        SSL = True    
        print("SSL: Enabled")
    else:
        print("SSL: Disabled")
    
#Matches a string from the response
def CheckOutput(injection_case, i):
    match_strings = injection_case.rule_args[i]
    
    start = time.time()
    while(time.time() - start < 5):
        if(injection_case.response != None):
            for string in match_strings:
                if string not in injection_case.response.content:
                    injection_case.result[i] = False
                    return
                
            injection_case.result[i] = True
            return

    print("Scan timed out...")
    injection_case.result[i] = False
    return

def CheckPageOutut(injection_case, i):
    url = GetURL(injection_case.rule_args[i][0])[0]
    match_strings = injection_case.rule_args[i][1:]
    try:
        page = requests.get(url, params={}, cookies={},
                                allow_redirects=True, timeout=5)

        page.raise_for_status()
        for string in match_string:
            if string not in response.content:
                injection_case.result[i] = False
                return
        
        injection_case.result[i] = True
        return

    except:
        injection_case.result[i] = False
        print("ERROR: Could not find page " + url)

#Matches the status code of the respone
def MatchStatusCode(injection_case, i):
    if injection_case.response.status_code in injection_case.rule_args[i]:
        injection_case.result[i] = True
    else:
        injection_case.result[i] = False

def ListenOnPort(injection_case, i):
    args = injection_case.rule_args[i]
    try:
         
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", args[0]))
        sck.settimeout(args[1])
        sock.listen(1)

        if(sock.accept()):
            injection_case.result[i] = True
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            return
            

    except socket.timeout:
        injection_case.result[i] = False
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        return
    
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
    print("Fuzzit Web Scanner v0.5 by iwakura1ain...")
    print("======== OPTIONS =====n===")
    GetArgs()
    
    if(TYPE in ["get", "post"]):
        url = GetURL(RHOST)[0]
        injection_points, non_injections = GetInjectionPoints(RHOST)

        print("\n======== Generating Injections ========")
        MakeInjectionValues(injection_points, 0, non_injections)
        PrintInjections(INJECTIONS)

        injections = []
        for injection_dict in INJECTIONS:
            injections.append(InjectionCase(injection_dict))
            
        print("\n======== Scanning RHOST ========")    
        for injection in injections:
            injection.Scan(url, injection.injection, COOKIE, HEADERS)
            injection.PrintResponse()
    
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




                
