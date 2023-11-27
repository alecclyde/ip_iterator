#!/usr/bin/env python3

import argparse
import ipaddress
import logging
import os
import signal
import subprocess
import sys
import threading

from colorama import init, Fore

init(autoreset=True)

BANNER = """

 /$$$$$$ /$$$$$$$        /$$$$$$ /$$                                    /$$                        
|_  $$_/| $$__  $$      |_  $$_/| $$                                   | $$                        
  | $$  | $$  \ $$        | $$ /$$$$$$    /$$$$$$   /$$$$$$  /$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$ 
  | $$  | $$$$$$$/        | $$|_  $$_/   /$$__  $$ /$$__  $$|____  $$|_  $$_/   /$$__  $$ /$$__  $$
  | $$  | $$____/         | $$  | $$    | $$$$$$$$| $$  \__/ /$$$$$$$  | $$    | $$  \ $$| $$  \__/
  | $$  | $$              | $$  | $$ /$$| $$_____/| $$      /$$__  $$  | $$ /$$| $$  | $$| $$      
 /$$$$$$| $$             /$$$$$$|  $$$$/|  $$$$$$$| $$     |  $$$$$$$  |  $$$$/|  $$$$$$/| $$      
|______/|__/            |______/ \___/   \_______/|__/      \_______/   \___/   \______/ |__/      
"""

# Global variable to track the execution state
is_interrupted = False

def signal_handler(sig, frame):
    stop_event.set()
    logging.info("Program interrupted by user.")
    sys.exit(0)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Flexible IP command executor",
        epilog="Example: ./ip_iterator.py --command 'cme smb <IP> -u username -p password --shares' --file ./iprange.txt --timeout 30 --threads 4"
    )
    parser.add_argument("--command", required=True, help="Command to execute with <IP> placeholder")
    parser.add_argument("--file", required=True, help="Path to the file containing IPs, CIDRs, or ranges")
    parser.add_argument("--timeout", type=int, default=None, help="Timeout in seconds for command execution (Default=No timeout)")
    parser.add_argument("--no-output", action="store_true", help="Execute commands without writing output files (Default=False)")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads for concurrent command execution (Default=1)")
    return parser.parse_args()

def load_ips(file_path):
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found."
        print(Fore.RED + error_message)
        logging.error(error_message)
        sys.exit(1)
        
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
       
        ips = [line.strip() for line in lines]

        processed_ips = set()  # Use set for deduplication
        for ip in ips:
            if "-" in ip:
                start_ip, end_ip = ip.split("-")
                ip_range = range(int(ipaddress.IPv4Address(start_ip.strip())), int(ipaddress.IPv4Address(end_ip.strip())) + 1)
                processed_ips.update(map(str, map(ipaddress.IPv4Address, ip_range)))
            else:
                processed_ips.update(map(str, ipaddress.ip_network(ip, strict=False)))

        return sorted(list(processed_ips))

    except Exception as e:
        error_message = f"An error occurred while loading the IPs from the file: {e}"
        print(Fore.RED + error_message)
        logging.error(error_message)
        sys.exit(1)

def execute_commands_thread(command, ips, timeout, no_output):
    for idx, ip in enumerate(ips, 1):
        if is_interrupted:
            break

        print(f"{threading.current_thread().name}: Trying IP {idx}/{len(ips)}: {ip}")
        full_command = command.replace("<IP>", ip)
        try:
            if no_output:
                # Run the command without capturing the output
                subprocess.run(full_command, shell=True, timeout=timeout)
            else:
                # Capture the output and write it to files
                output = subprocess.run(full_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
                if output.stdout:
                    try:
                        with open(f"{ip}_output.txt", "w") as file:
                            file.write(output.stdout)
                    except Exception as e:
                        print(Fore.RED + f"Error occurred while writing output for IP '{ip}': {e}")
                    try:
                        with open("combined_output.txt", "a") as file:
                            file.write(f"{ip} - {threading.current_thread().name}: IP {idx}/{len(ips)} Output:\n{output.stdout}\n\n")
                    except Exception as e:
                        print(Fore.RED + f"Error occurred while writing combined output for IP '{ip}': {e}")
                else:
                    try:
                        with open("combined_output.txt", "a") as file:
                            file.write(f"{threading.current_thread().name}: IP {idx}/{len(ips)} Output: No output\n\n")
                    except Exception as e:
                        print(Fore.RED + f"Error occurred while writing combined output for IP '{ip}': {e}")
        except subprocess.TimeoutExpired:
            print(Fore.RED + f"{threading.current_thread().name}: IP {ip} timed out.")
            try:
                with open("combined_output.txt", "a") as file:
                    file.write(f"{threading.current_thread().name}: IP {idx}/{len(ips)} Timeout: The command execution timed out.\n\n")
            except Exception as e:
                print(Fore.RED + f"Error occurred while writing combined output for IP '{ip}' timeout: {e}")
        except Exception as e:
            print(Fore.RED + f"Error occurred while executing command for IP '{ip}': {e}")

def execute_commands(command, ips, timeout, no_output, threads):
    total_ips = len(ips)
    ips_per_thread = (total_ips + threads - 1) // threads
    threads_list = []
    
    for i in range(0, total_ips, ips_per_thread):
        ips_subset = ips[i:i+ips_per_thread]
        thread = threading.Thread(target=execute_commands_thread, args=(command, ips_subset, timeout, no_output), name=f"Thread-{i//ips_per_thread+1}")
        threads_list.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads_list:
        thread.join()

    if is_interrupted:
        print(Fore.RED + "Execution interrupted. Results up to this point have been saved.")
    else:
        print(Fore.GREEN + "Execution complete. Results saved in individual and combined output files.")

def reset_terminal_settings():
    # Restore the terminal settings to their default values
    import os
    os.system("stty sane")

def setup_logging():
    logging.basicConfig(filename="ip_iterator.log", filemode="a", format="%(asctime)s [%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)

def main():
    setup_logging()
    # Register the signal handler for KeyboardInterrupt (Ctrl+C)
    signal.signal(signal.SIGINT, signal_handler)

    print(BANNER)
    try:
        args = parse_arguments()
        if not args.command or not args.file:
            error_message = "Error: Please provide both the command and the file path. Use -h for help."
            print(Fore.RED + error_message)
            logging.error(error_message)
            sys.exit(1)
        ips = load_ips(args.file)
        execute_commands(args.command, ips, args.timeout, args.no_output, args.threads)
    except KeyboardInterrupt:
        # Ignore KeyboardInterrupt here as it is handled by the signal handler
        pass
    except Exception as e:
        error_message = f"An error occurred: {e}"
        print(Fore.RED + error_message)
        logging.exception(error_message)
        sys.exit(1)

if __name__ == "__main__":
    main()
    reset_terminal_settings()
