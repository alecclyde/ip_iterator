#!/usr/bin/env python3

import argparse
import logging
import os
import signal
import subprocess
import sys
import threading

from colorama import init, Fore

init(autoreset=True)

BANNER = """
 # [Your banner here]
"""

# Global variable to track the execution state
is_interrupted = False

def signal_handler(sig, frame):
    stop_event.set()
    logging.info("Program interrupted by user.")
    sys.exit(0)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Flexible Domain command executor",
        epilog="Example: ./domain_iterator.py --command 'ping <DOMAIN>' --file ./domains.txt --timeout 30 --threads 4"
    )
    parser.add_argument("--command", required=True, help="Command to execute with <DOMAIN> placeholder")
    parser.add_argument("--file", required=True, help="Path to the file containing domain names")
    parser.add_argument("--timeout", type=int, default=None, help="Timeout in seconds for command execution (Default=No timeout)")
    parser.add_argument("--no-output", action="store_true", help="Execute commands without writing output files (Default=False)")
    parser.add_argument("--threads", type=int, default=1, help="Number of threads for concurrent command execution (Default=1)")
    return parser.parse_args()

def load_domains(file_path):
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found."
        print(Fore.RED + error_message)
        logging.error(error_message)
        sys.exit(1)
        
    try:
        with open(file_path, "r") as file:
            domains = [line.strip() for line in file.readlines() if line.strip()]
        return sorted(list(set(domains)))  # Deduplicate and sort the list

    except Exception as e:
        error_message = f"An error occurred while loading domains from the file: {e}"
        print(Fore.RED + error_message)
        logging.error(error_message)
        sys.exit(1)

def execute_commands_thread(command, domains, timeout, no_output):
    for idx, domain in enumerate(domains, 1):
        if is_interrupted:
            break

        print(f"{threading.current_thread().name}: Trying domain {idx}/{len(domains)}: {domain}")
        full_command = command.replace("<DOMAIN>", domain)
        try:
            if no_output:
                subprocess.run(full_command, shell=True, timeout=timeout)
            else:
                output = subprocess.run(full_command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
                if output.stdout:
                    try:
                        with open(f"{domain}_output.txt", "w") as file:
                            file.write(output.stdout)
                    except Exception as e:
                        print(Fore.RED + f"Error occurred while writing output for domain '{domain}': {e}")
                    try:
                        with open("combined_output.txt", "a") as file:
                            file.write(f"{domain} - {threading.current_thread().name}: Domain {idx}/{len(domains)} Output:\n{output.stdout}\n\n")
                    except Exception as e:
                        print(Fore.RED + f"Error occurred while writing combined output for domain '{domain}': {e}")
                else:
                    try:
                        with open("combined_output.txt", "a") as file:
                            file.write(f"{threading.current_thread().name}: Domain {idx}/{len(domains)} Output: No output\n\n")
                    except Exception as e:
                        print(Fore.RED + f"Error occurred while writing combined output for domain '{domain}': {e}")
        except subprocess.TimeoutExpired:
            print(Fore.RED + f"{threading.current_thread().name}: Domain {domain} timed out.")
            try:
                with open("combined_output.txt", "a") as file:
                    file.write(f"{threading.current_thread().name}: Domain {idx}/{len(domains)} Timeout: The command execution timed out.\n\n")
            except Exception as e:
                print(Fore.RED + f"Error occurred while writing combined output for domain '{domain}' timeout: {e}")
        except Exception as e:
            print(Fore.RED + f"Error occurred while executing command for domain '{domain}': {e}")

def execute_commands(command, domains, timeout, no_output, threads):
    total_domains = len(domains)
    domains_per_thread = (total_domains + threads - 1) // threads
    threads_list = []
    
    for i in range(0, total_domains, domains_per_thread):
        domains_subset = domains[i:i+domains_per_thread]
        thread = threading.Thread(target=execute_commands_thread, args=(command, domains_subset, timeout, no_output), name=f"Thread-{i//domains_per_thread+1}")
        threads_list.append(thread)
        thread.start()

    for thread in threads_list:
        thread.join()

    if is_interrupted:
        print(Fore.RED + "Execution interrupted. Results up to this point have been saved.")
    else:
        print(Fore.GREEN + "Execution complete. Results saved in individual and combined output files.")

def reset_terminal_settings():
    import os
    os.system("stty sane")

def setup_logging():
    logging.basicConfig(filename="domain_iterator.log", filemode="a", format="%(asctime)s [%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S", level=logging.INFO)

def main():
    setup_logging()
    signal.signal(signal.SIGINT, signal_handler)

    print(BANNER)
    try:
        args = parse_arguments()
        if not args.command or not args.file:
            error_message = "Error: Please provide both the command and the file path. Use -h for help."
            print(Fore.RED + error_message)
            logging.error(error_message)
            sys.exit(1)
        domains = load_domains(args.file)
        execute_commands(args.command, domains, args.timeout, args.no_output, args.threads)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        error_message = f"An error occurred: {e}"
        print(Fore.RED + error_message)
        logging.exception(error_message)
        sys.exit(1)

if __name__ == "__main__":
    main()
    reset_terminal_settings()
