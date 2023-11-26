# Import necessary libraries
from pwn import *
import sys
import hashlib
import os
import time
import multiprocessing
import itertools
import string
from datetime import datetime
import argparse

# ASCII art for aesthetic display
ascii_art = '''

██╗░░██╗░█████╗░░██████╗██╗░░██╗██╗░░██╗░█████╗░░██╗░░░░░░░██╗██╗░░██╗
██║░░██║██╔══██╗██╔════╝██║░░██║██║░░██║██╔══██╗░██║░░██╗░░██║██║░██╔╝
███████║███████║╚█████╗░███████║███████║███████║░╚██╗████╗██╔╝█████═╝░
██╔══██║██╔══██║░╚═══██╗██╔══██║██╔══██║██╔══██║░░████╔═████║░██╔═██╗░
██║░░██║██║░░██║██████╔╝██║░░██║██║░░██║██║░░██║░░╚██╔╝░╚██╔╝░██║░╚██╗
╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚═╝░░╚═╝

'''

# Decorator for logging execution time
def logger(func):
    def wrapper(*args, **kwargs):
        # Log the start time
        print("-" * 50)
        print("> Execution started {}".format(datetime.today().strftime("%Y-%m-%d %H:%M:%S")))
        # Execute the function
        result = func(*args, **kwargs)
        # Log the completion time
        print("> Execution completed {}".format(datetime.today().strftime("%Y-%m-%d %H:%M:%S")))
        print("-" * 50)
        return result
    return wrapper

# Function to hash a password using the specified algorithm
def hash_password(password, algorithm):
    if algorithm in hashlib.algorithms_guaranteed:
        # Create a new hasher object and update it with the password
        hasher = hashlib.new(algorithm)
        hasher.update(password.encode())
        # Return the hexadecimal representation of the hashed password
        return hasher.hexdigest()
    else:
        # Print an error message and exit if the hashing algorithm is unsupported
        log.failure(f"Unsupported hashing algorithm: {algorithm}")
        sys.exit(1)

# Function to perform the brute-force attack
def brute_force(target_hash, password_list=None, use_multiprocessing=False, hashing_algorithm=None, case_sensitive=True):
    attempts = 0
    start_time = time.time()

    with log.progress(f"Attempting to crack hash: {target_hash}!") as p:
        if password_list:
            for password in password_list:
                # Generate both lowercase and uppercase variations of the password if case-sensitive
                if case_sensitive:
                    variations = [password]
                else:
                    variations = [''.join(case) for case in itertools.product(*zip(password.lower(), password.upper()))]

                for case_password in variations:
                    password_hash = hash_password(case_password, hashing_algorithm)
                    p.status(f"[{attempts}] {case_password} == {password_hash}")

                    if password_hash == target_hash:
                        p.success(f"\nPassword hash found after {attempts} attempts!")
                        p.success(f"Time taken: {time.time() - start_time:.2f} seconds")
                        return case_password

                    attempts += 1

                    if attempts % 100 == 0:
                        p.status(f"[{attempts}] {case_password}")

        else:
            p.failure("No password list provided for brute-force attack.")

    return None

# Function to generate passwords based on specific criteria
def generate_passwords(min_length, max_length, character_set="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"):
    passwords = []
    for length in range(min_length, max_length + 1):
        passwords.extend([''.join(candidate) for candidate in itertools.product(character_set, repeat=length)])
    return passwords

# Function to run the brute-force attack with multiprocessing
def run_brute_force_multiprocessing(target_hash, min_length, max_length, character_set="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", hashing_algorithm=None, case_sensitive=True):
    password_list = generate_passwords(min_length, max_length, character_set)

    if password_list:
        # Create a multiprocessing pool
        pool = multiprocessing.Pool()
        chunk_size = len(password_list) // multiprocessing.cpu_count()

        # Distribute password list among processes
        password_chunks = [password_list[i:i + chunk_size] for i in range(0, len(password_list), chunk_size)]

        # Use multiprocessing to run the brute-force attack
        results = pool.starmap(
            brute_force,
            [(target_hash, chunk, False, hashing_algorithm, case_sensitive) for chunk in password_chunks]
        )

        # Close and join the pool
        pool.close()
        pool.join()

        for result in results:
            if result:
                return result
    else:
        print("No password list provided for multiprocessing.")

    return None

# Interactive mode for user input
def interactive_mode():
    target_hash = input("Enter the target hash: ")
    attack_type = input("Choose attack type (bruteforce/dictionary): ").lower()

    min_length = 0  # Set default values
    max_length = 0
    character_set = ""
    password_list = None

    if attack_type == 'dictionary':
        password_file = input("Enter the path to the password file: ")
        with open(password_file, "r", encoding="latin-1", errors="ignore") as password_file:
            password_list = [line.strip() for line in password_file]
    elif attack_type == 'bruteforce':
        print("Generating custom password list...")
        while True:
            length_input = input("Enter the password length or range (e.g., 6 or 5-10): ")
            if '-' in length_input:
                try:
                    min_length, max_length = map(int, length_input.split('-'))
                    if min_length <= max_length:
                        break
                    else:
                        log.failure("Invalid input for password range. Minimum length should be less than or equal to the maximum length.")
                except ValueError:
                    log.failure("Invalid input for password range. Please enter a valid integer range.")
            else:
                try:
                    min_length = max_length = int(length_input)
                    break
                except ValueError:
                    log.failure("Invalid input for password length. Please enter a valid integer.")

        character_set = input("Enter the character set for passwords: ")
        while not character_set.strip():
            log.failure("Empty character set. Please enter a specific character set.")
            character_set = input("Enter the character set for passwords: ")

        password_list = generate_passwords(min_length, max_length, character_set)
    else:
        log.failure("Invalid attack type. Exiting.")
        sys.exit(1)

    hashing_algorithm = input("Choose hashing algorithm from {} : ".format(hashlib.algorithms_guaranteed))
    case_sensitive = input("Do you want a case-sensitive brute-force attack? (y/n): ").lower() == 'y'

    return target_hash, attack_type, password_list, min_length, max_length, character_set, hashing_algorithm, case_sensitive

# Argument parser for command-line options
def parse_args():
    parser = argparse.ArgumentParser(
        description="HashHawk - Password Hash Cracking Tool",
        usage="%(prog)s target_hash {bruteforce,dictionary}",
    )

    if len(sys.argv) == 1:
        # If no command-line arguments, prompt the user for input
        target_hash = input("Enter the target hash: ")
        attack_type = input("Choose attack type (bruteforce/dictionary): ").lower()
        return argparse.Namespace(target_hash=target_hash, attack_type=attack_type)
    else:
        parser.add_argument("target_hash", help="Target hash to crack")
        parser.add_argument(
            "attack_type",
            nargs="?",  # Make the argument optional
            choices=["bruteforce", "dictionary"],
            help="Choose attack type (bruteforce or dictionary)",
        )

        return parser.parse_args()

# Main function
@logger
def main():
    print(ascii_art)

    args = parse_args()
    target_hash = args.target_hash
    attack_type = args.attack_type

    if not attack_type:
        # If attack_type is not provided, prompt the user for input
        attack_type = input("Choose attack type (bruteforce/dictionary): ").lower()

    if attack_type == 'dictionary':
        password_file = input("Enter the path to the password file: ")
        with open(password_file, "r", encoding="latin-1", errors="ignore") as password_file:
            password_list = [line.strip() for line in password_file]
    elif attack_type == 'bruteforce':
        print("Generating custom password list...")
        while True:
            length_input = input("Enter the password length or range (e.g., 6 or 5-10): ")
            if '-' in length_input:
                try:
                    min_length, max_length = map(int, length_input.split('-'))
                    if min_length <= max_length:
                        break
                    else:
                        print("Invalid input for password range. Minimum length should be less than or equal to the maximum length.")
                except ValueError:
                    print("Invalid input for password range. Please enter a valid integer range.")
            else:
                try:
                    min_length = max_length = int(length_input)
                    break
                except ValueError:
                    print("Invalid input for password length. Please enter a valid integer.")

        character_set = input("Enter the character set for passwords: ")
        while not character_set.strip():
            print("Empty character set. Please enter a specific character set.")
            character_set = input("Enter the character set for passwords: ")

        password_list = generate_passwords(min_length, max_length, character_set)
    else:
        print("Invalid attack type. Exiting.")
        sys.exit(1)

    hashing_algorithm = input(f"Choose hashing algorithm from {hashlib.algorithms_guaranteed} : ")

    case_sensitive = input("Do you want a case-sensitive brute-force attack? (y/n): ").lower() == 'y'

    if attack_type == 'bruteforce':
        if multiprocessing.cpu_count() > 1:
            password = run_brute_force_multiprocessing(target_hash, min_length, max_length, character_set, hashing_algorithm, case_sensitive)
        else:
            password = brute_force(target_hash, password_list, False, hashing_algorithm, case_sensitive)

    elif attack_type == 'dictionary':
        password = brute_force(target_hash, password_list, False, hashing_algorithm, case_sensitive)

    if password:
        print(f"[+] Password found: {password}")
    else:
        print("[-] Password not found.")

if __name__ == "__main__":
    main()
