# HashHawk - Password Hash Cracking Tool

HashHawk is a Python-based password hash cracking tool that supports both dictionary and brute-force attacks. It provides a simple and interactive interface for users to crack password hashes using various algorithms and attack methods.

## Features

- **Brute-force Attack:** Generate custom password lists and perform brute-force attacks on hashed passwords.
- **Dictionary Attack:** Use an existing password dictionary file for efficient password cracking.
- **Hashing Algorithms:** Supports various hashing algorithms available in the hashlib library.
- **Interactive Mode:** User-friendly interactive mode for easy input and execution.
- **Multiprocessing Support:** Utilizes multiprocessing for faster brute-force attacks on multi-core systems.

## Dependencies

Make sure to have the following Python libraries installed:

- [Pwntools](https://docs.pwntools.com/): A CTF framework and exploit development library.
- [hashlib](https://docs.python.org/3/library/hashlib.html): Provides secure hash and message digest algorithms.
- [multiprocessing](https://docs.python.org/3/library/multiprocessing.html): Supports the spawning of processes using an API similar to the threading module.
- [itertools](https://docs.python.org/3/library/itertools.html): Provides functions for creating iterators for efficient looping.
- [string](https://docs.python.org/3/library/string.html): Provides common string operations.
- [datetime](https://docs.python.org/3/library/datetime.html): Supplies classes for manipulating dates and times.
- [argparse](https://docs.python.org/3/library/argparse.html): Parser for command-line options, arguments, and sub-commands.

## Usage

### Command Line

```bash
python hashhawk.py target_hash {bruteforce,dictionary}
```

- `target_hash`: The hash to be cracked.
- `bruteforce`: Perform a brute-force attack.
- `dictionary`: Perform a dictionary attack.

### Interactive Mode

Run the script without command-line arguments to enter interactive mode.

```bash
python hashhawk.py
```

Follow the prompts to enter the target hash, attack type, and other relevant information.

## Dependencies

- **Python:** HashHawk is written in Python.
- **pwntools:** A powerful library for interacting with binary programs.

Install the required dependencies using the following command:

```bash
pip install pwntools
```

## Example

1. Run the script interactively:

```bash
python hashhawk.py
```

2. Enter the target hash, choose the attack type, and provide additional information as prompted.

3. Let HashHawk perform the password cracking.

#

## Disclaimer

This tool is intended for educational and ethical use only. Unauthorized access to computer systems and networks is illegal.


## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

---

Feel free to contribute, report issues, or suggest improvements!