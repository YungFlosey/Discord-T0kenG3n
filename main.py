import os, requests, base64, json, httpx, re
from colorama import Fore, Style
from PyMailGw import MailGwApi
from user_agent import generate_navigator_js
from twocaptcha import TwoCaptcha
from invisifox import InvisiFox
from discord_build_info_py import *
import capmonster_python
from capmonster_python import HCaptchaTask


if __name__ == '__main__':

    class Settings():
        DATA = {'2_captcha_api_key' : '',
                'invisifox_api_key' : '',
                    'r_site_key'    : '4c672d35-0701-42b2-88c3-78380b0db560',
                    'v_site_key'    : 'f5561ba9-8f1e-40ca-9b5b-a0b3f719ef34'
    
        }

    class ui():
        
        def __init__(self):
            pass

        def banner():

            print(Fore.RED)
            print('▄▄▄█████▓ ▒█████   ██ ▄█▀▓█████  ███▄    █   ▄████ ▓█████  ███▄    █ ')
            print('▓  ██▒ ▓▒▒██▒  ██▒ ██▄█▒ ▓█   ▀  ██ ▀█   █  ██▒ ▀█▒▓█   ▀  ██ ▀█   █ ')
            print('▒ ▓██░ ▒░▒██░  ██▒▓███▄░ ▒███   ▓██  ▀█ ██▒▒██░▄▄▄░▒███   ▓██  ▀█ ██▒')
            print('░ ▓██▓ ░ ▒██   ██░▓██ █▄ ▒▓█  ▄ ▓██▒  ▐▌██▒░▓█  ██▓▒▓█  ▄ ▓██▒  ▐▌██▒')
            print('  ▒██▒ ░ ░ ████▓▒░▒██▒ █▄░▒████▒▒██░   ▓██░░▒▓███▀▒░▒████▒▒██░   ▓██░')
            print('  ▒ ░░   ░ ▒░▒░▒░ ▒ ▒▒ ▓▒░░ ▒░ ░░ ▒░   ▒ ▒  ░▒   ▒ ░░ ▒░ ░░ ▒░   ▒ ▒ ')
            print('    ░      ░ ▒ ▒░ ░ ░▒ ▒░ ░ ░  ░░ ░░   ░ ▒░  ░   ░  ░ ░  ░░ ░░   ░ ▒░')
            print('  ░      ░ ░ ░ ▒  ░ ░░ ░    ░      ░   ░ ░ ░ ░   ░    ░      ░   ░ ░ ')
            print(Style.RESET_ALL)

        def menu():

            print('1. Create Account')
            print('2. Gen-Mode')
            print('3. Input Config')
            print('4. Back to Home everywhere')


        def config():

            exit = False

            def build(two, inv,email):
                dict = {
                    "2_captcha_api_key"       :   f"{two}",
                    "invisifox_api_key"       :   f"{inv}",
                    "email"                   :   f"{email}",
                    "r_captcha_url"           :   "https://discord.com/register",
                    "v_captcha_url"           :   "https://discord.com/verify"}
                return dict

            def write(dict1):

                with open("config.json", "w") as f:
  
                    json.dump(dict1, f, indent = 6)
  
                f.close()

            def inv():
                print('')
                eingabe = input('Api Key eingeben:')
                print('')
                return eingabe
            def two():
                print('')
                eingabe = input('Api Key eingeben:')
                print('')
                return eingabe
            def gmail():
                print('')
                eingabe = input('Gmail eingeben:')
                email = eingabe[:-10]
                return email
            def c_captcha():
                print('1. 2Captcha')
                print('2. Invisifox')
                print('More Apis will be added in the future')
                eingabe = input('')
                return eingabe
            def c_email():
                print('')
                print('1. Gmail(No verification atm)')
                print('2. Integrated TempMail')
                eingabe = input('')
                return eingabe

            invcaptchakey = 'Not assigned'
            twocaptchakey = 'Not assigned'
            email = 'Not assigned'

            ccaptch = c_captcha()
            if ccaptch == '1':
                twocaptchakey = two()
                if twocaptchakey == '4':
                    exit = True
                    return exit
                else:
                    pass
            elif ccaptch == '2':
                invcaptchakey = inv()
                if invcaptchakey == '4':
                    exit = True
                    return exit
                else:
                    pass
            elif ccaptch == '4':
                exit = True
                return exit
            cemail = c_email()
            if cemail == '1':
                email = gmail()
            if cemail == '2':
                pass
            if cemail == '4':
                exit = True
                return exit
            
            dict = build(two=twocaptchakey,inv=invcaptchakey,email=email)
            write(dict1=dict)
            print('Config updated')
            print('')

    class get():

        def __init__(self):
            pass

        def get_email_normal(gmail, counter):
            email = f"{gmail}+" + str(counter) + "@gmail.com"
            return email

        def get_username():
            r=requests.get('https://story-shack-cdn-v2.glitch.me/generators/username-generator?')
            return r.json()["data"]["name"]

        def get_useragent():
            useragent = generate_navigator_js()
            return useragent

        def get_client():
            data=getClientData('stable')
            return data

        def get_fingerprint():
            fingerprint = httpx.get('https://ptb.discord.com/api/v9/experiments', timeout = 10 ).json()['fingerprint']
            return fingerprint
    
        def get_cookies():
            r = requests.get(f'https://discord.com/register').headers['set-cookie']

            sep    = r.split(";")
            sx     = sep[0]
            sx2    = sx.split("=")
            dcf    = sx2[1]
            split  = sep[6]
            split2 = split.split(",")
            split3 = split2[1]
            split4 = split3.split("=")
            sdc    = split4[1]

            return dcf, sdc

        
        def get_email_verification(responseLink):

            r = requests.get(responseLink)

            token = r.url.split("#token=")[1]
            return token

    class listener():

        def __init__(self,proxy):
            self.__mail = MailGwApi(proxy=f'http://{proxy}', timeout=30)

        def get_email(self):
            api = self.__mail
            mail = api.get_mail()
            return mail

        def get_messages(self):
            api = self.__mail
            messages = api.fetch_inbox()
            return messages

        def search_for_discord(self):

            api = self.__mail
            
            for mail in api.fetch_inbox():
                if mail["from"]["address"] == 'noreply@discord.com':
                    content_email = api.get_message_content(mail['id'])       
                    linklist = re.findall(r'(https?://\S+)',content_email)   
                    link = linklist[0]

                    
                    return link


    class register():

        def __init__(self):
            pass

        def create_account(pload, headers, proxy):

            r = requests.post('https://discord.com/api/v9/auth/register',json=pload, headers=headers, proxies=proxy)
            r_dict = r.json()

            return r_dict['token']

        def verify_account(proxy, v_token, useragent, captcha_key):

            pload = {
                            'captcha_key'           : f'{captcha_key}',
                            'token'                 : f'{v_token}',
                    }

            header = {
                            'Authorization'         : f'',
                            'User-Agent'            : f'{useragent}',
                            'Referer'               : f'https://discord.com/verify',
                            'X-Discord-Locale'      : f'en-US',
                            'TE'                    : f'trailers',
                            'X-Debug-Options'       : f'bugReporterEnabled',
                            'Host'                  : f'discord.com',
                            'DNT'                   : f'1',
                            'Content-Length'        : f'161',
                            'Accept'                : f'*/*',
                            'Accept-Encoding'       : f'gzip, deflate, br',
                            'Accept-Language'       : f'en-US,en;q=0.5',
                            'Connection'            : f'keep-alive',
                    }

            r = requests.post('https://discord.com/api/v9/auth/verify',json = pload, headers = header, proxies = proxy)
            return r



        
    class create():

        def __init__(self):
            pass

        def create_pload(fingerprint, username, captcha_key, email):
            pload = {'fingerprint':f'{fingerprint}',
                    "email":f'{email}',
                    'captcha_key':f'{captcha_key}',
                    "username":f'{username}',
                    "password":"D1scord1234",
                    "invite":"null",
                    "consent":f'{True}',
                    "date_of_birth":"2001-05-11",
                    "gift_code_sku_id":'null',}
            return pload

        def create_xprobs(useragent, clientnumber):
            f = useragent
            c = clientnumber

            uo = f['appCodeName']
            up = f['platform']
            ua = f['userAgent']
            ubv = f['appVersion'].split(" ")[0]
            osv = f['userAgent'].split("/")[1].split(" ")[0]
            cbn = c[0]  

            dict = {"os":f'{uo}',
                    "browser":f'{up}',
                    "device": "",
                    "browser_user_agent":f'{up}',
                    "browser_version":f'{ubv}',
                    "os_version": f'{osv}',
                    "referrer": "",
                    "referring_domain": "",
                    "referrer_current": "",
                    "referring_domain_current": "",
                    "release_channel": "stable",
                    "client_build_number": f'{cbn}',
                    "client_event_source": "null"
                }
            data =json.dumps(dict)

            enc = data.encode()  

            b = base64.b64encode(enc)
            bs = b.decode("utf-8")
            return bs

        

        def create_header(useragent, xprobs, fingerprint, cookies):

            dcf = cookies[0]
            sdc = cookies[1]
            useragent = useragent['userAgent']
            
            header = {  'User-Agent'            : f'%s' % {useragent},
                        'Origin'                : f'https://discord.com',
                        'Referer'               : '',
                        'Content-Type'          : f'application/json',
                        'Sec-Fetch-Dest'        : f'empty',
                        'Sec-Fetch-Mode'        : f'cors',
                        'Sec-Fetch-Site'        : f'same-origin', 
                        'X-Fingerprint'         : f'%s' % {fingerprint},
                        'X-Discord-Locale'      : f'en-US',
                        'TE'                    : f'trailers',
                        'X-Debug-Options'       : f'bugReporterEnabled',
                        'Host'                  : f'discord.com',
                        'DNT'                   : f'1',
                        'Content-Length'        : f'161',
                        'Accept'                : f'*/*',
                        'Accept-Encoding'       : f'gzip, deflate, br',
                        'Accept-Language'       : f'en-US,en;q=0.5',
                        'Connection'            : f'keep-alive',
                        'X-Super-Properties'    : f'%s' % {xprobs},
                        'Cookie'                : f'__dcfduid={dcf}; __sdcfduid={sdc}; _gcl_au=1.1.33345081.1647643031; _ga=GA1.2.291092015.1647643031; _gid=GA1.2.222777380.1647643031; OptanonConsent=isIABGlobal=false&datestamp=Fri+Mar+18+2022+18%3A53%3A43+GMT-0400+(%E5%8C%97%E7%BE%8E%E4%B8%9C%E9%83%A8%E5%A4%8F%E4%BB%A4%E6%97%B6%E9%97%B4)&version=6.17.0&hosts=&landingPath=https%3A%2F%2Fdiscord.com%2F&groups=C0001%3A1%2CC0002%3A1%2CC0003%3A1; __cf_bm=.fksdoBlzBs1zuhiY0rYFqFhDkstwwQJultZ756_yrw-1647645226-0-AaluVZQHZhOL5X4GXWxqEIC5Rp3/gkhKORy7WXjZpp5N/a4ovPxRX6KUxD/zpjZ/YFHBokF82hLwBtxtwetYhp/TSrGowLS7sC4nnLNy2WWMpZSA7Fv1tMISsR6qBZdPvg==; locale=en-US',
                        'Authorization'.lower() : f'undefined'
                       }
            return header

    class captcha():

        def __init__(self, sitekey, url):
    
            self.__sitekey = sitekey 
            self.__url = url
            

        def solve2(self, apikey, proxy):
            solver = TwoCaptcha(apikey)
            result = solver.hcaptcha(sitekey=self.__sitekey,
                            url=self.__url,proxy=proxy)
            return result['code']


        def solve(self, api_key, proxy):
            bot = InvisiFox()
            bot.apiKey = api_key

            solution = bot.solveHCaptcha(sitekey=self.__sitekey,pageurl=self.__url,proxy=proxy)
            return solution

        def capsolve(self, api_key, proxy):
            capmonster = HCaptchaTask(api_key)
            capmonster.set_proxy("http", "8.8.8.8", 8080)
            capmonster.set_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0")
            task_id = capmonster.create_task("website_url", "website_key")
            result = capmonster.join_task_result(task_id)
            return (result.get("gRecaptchaResponse"))


    def get_proxy_var_value(filename="proxyvarstore.dat"):
        with open(filename, "a+") as f:
            f.seek(0)
            val = int(f.read() or 0) + 1
            f.seek(0)
            f.truncate()
            f.write(str(val))
            return val

    def get_var_value(filename="varstore.dat"):
        with open(filename, "a+") as f:
            f.seek(0)
            val = int(f.read() or 0) + 1
            f.seek(0)
            f.truncate()
            f.write(str(val))
            return val

    def read_proxy(filename,countervalue):
        file = open(filename)
        content = file.readlines()
        return(content[countervalue])

    def main():
        with open('config.json', 'r+') as f :
            data = json.load(f)

        print('Fetching Proxy from file')
        var = get_proxy_var_value()
        counter = get_var_value()
        proxyvariable = (read_proxy('proxies.txt',var))
        print(proxyvariable)
        two_cproxy ={
            'type': 'HTTPS',
            'uri': proxyvariable 
        }
        inv_cproxy = f'http://{proxyvariable}'
        rproxy ={
            'http': f'http://{proxyvariable}',
            'https': f'http://{proxyvariable}',
        }
        
        Get = get
        
        print('Generating email')
        Listener = listener(proxy = proxyvariable)
        email = Listener.get_email()
        #email = Get.get_email_normal(counter)

        print(email)
        fingerprint = Get.get_fingerprint()
        username = Get.get_username()
        useragent = Get.get_useragent()
        clientnumber = Get.get_client()
        cookies = Get.get_cookies()

        print('Solving Captcha...')
        two_c_apikey = data['2_captcha_api_key']
        inv_api_key = data['invisifox_api_key']
        r_sitekey = Settings.DATA['r_site_key']
        
        r_captchaurl = data['r_captcha_url']
        R_Captcha = captcha(sitekey=r_sitekey, url=r_captchaurl)
        r_captchakey = R_Captcha.solve(api_key=inv_api_key, proxy=inv_cproxy)
        if r_captchakey is not None:
            print('Captcha solved!')
        

        Create = create
        pload = Create.create_pload(fingerprint=fingerprint, username=username, captcha_key=r_captchakey, email=email)
        xprobs =Create.create_xprobs(useragent=useragent, clientnumber=clientnumber)
        header = Create.create_header(useragent=useragent, xprobs=xprobs, fingerprint=fingerprint, cookies=cookies)


        Reg = register
        token = Reg.create_account(pload=pload, headers=header, proxy=rproxy)
        print('Account created')
        print(token)
        print('Verify Account...')
        
        responselink = Listener.search_for_discord()
        
        v_token = Get.get_email_verification(responseLink=responselink)


        v_sitekey = Settings.DATA['v_site_key']
        v_captcha_url = data['v_captcha_url']
        V_Captcha = captcha(sitekey=v_sitekey, url=v_captcha_url)
        print('Solving Captcha...')
        v_captchakey = V_Captcha.solve(api_key=inv_api_key, proxy=inv_cproxy)
        if v_captchakey is not None:
            print('Captcha solved!')

        verify = Reg.verify_account(v_token=v_token, useragent=useragent, captcha_key=v_captchakey, proxy=rproxy)
        if verify == '<Response [200]>':
            print('Account verified!')


        

        
        return token

    
    def mainmenu():
        Main = ui
        Main.banner()
        Main.menu()
        eingabe = input()
        if eingabe == '1':
            token = main()
            print(token)
        if eingabe == '2':
            pass
        if eingabe == '3':
            exit = Main.config() 
            if exit is True:
                mainmenu()
            mainmenu()
        if eingabe == '4':
            mainmenu()
            

    mainmenu() 

 
    

    







