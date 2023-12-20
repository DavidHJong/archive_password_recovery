import time
import signal
import sys
from argparse import ArgumentParser
from zipfile import ZipFile
import py7zr
import rarfile  
from multiprocessing import Process, Manager, Lock

# Set a higher recursion limit (if needed)
sys.setrecursionlimit(999999999)

class PasswordCracker:
    """A class for cracking password-protected archives."""

    def __init__(self, archive, dictionary, output, process_id, total_processes, max_passwords, log_lock, shared_dict):
        """
        Initialize the PasswordCracker object.

        Args:
            archive (str): The path to the archive file.
            dictionary (str): The path to the dictionary file containing passwords.
            output (str): The path to the output directory for extracted files.
            process_id (int): The ID of the current process.
            total_processes (int): The total number of processes.
            max_passwords (int): The maximum number of passwords to check.
            log_lock (threading.Lock): A lock for thread-safe logging.
            shared_dict (dict): A shared dictionary for inter-process communication.

        """
        self.archive = archive
        self.dictionary = dictionary
        self.output = output
        self.process_id = process_id
        self.total_processes = total_processes
        self.max_passwords = max_passwords
        self.log_lock = log_lock
        self.shared_dict = shared_dict
        self.checked_passwords = 0
        self.start_time = time.time()
        with open(self.dictionary, 'r') as f:
            self.lines = f.read().splitlines()

    def handle_ctrlc(self, signal, frame):
        """Gracefully exit the current operation when Ctrl+C is pressed."""
        self.shared_dict['stop_execution'] = True
        print("\nUser cancelled operation.")

    def crack(self):
        """Crack the password-protected archive."""
        if self.archive.endswith(".7z"):
            self._crack_7z()
        elif self.archive.endswith('.zip'):
            self._crack_zip()
        elif self.archive.endswith('.rar'):  # Add this condition
            self._crack_rar()               # Call the method to crack RAR

    def _crack_7z(self):
        """Crack the 7z archive."""
        self._crack_archive(py7zr.SevenZipFile)

    def _crack_zip(self):
        """Crack the zip archive."""
        self._crack_archive(ZipFile, encode_password=True)

    def _crack_rar(self):
        """Crack the RAR archive."""
        self._crack_archive(rarfile.RarFile, encode_password=True)

    def estimated_total_checked(self):
        """Estimate the total number of passwords checked across all processes."""
        return self.checked_passwords * self.total_processes

    def _crack_archive(self, archive_class, encode_password=False):
        """
        Crack the password-protected archive using the specified archive class.

        Args:
            archive_class (class): The class representing the archive format.
            encode_password (bool, optional): Whether to encode the password as UTF-8. Defaults to False.

        """
        # Filter lines for this process using interweaving distribution
        segment_lines = self.lines[self.process_id:self.max_passwords:self.total_processes]
        
        print(f"Process {self.process_id}: {len(segment_lines)} passwords to check. \t{len(self.lines[:self.max_passwords])} in total.")

        for password in segment_lines:
            if self.shared_dict.get('stop_execution', False):
                break
            try:
                with archive_class(self.archive, mode='r', password=password.encode("utf-8") if encode_password else password) as archive:
                    archive.extractall(self.output)
            except Exception as e:
                self.checked_passwords += 1
                if self.checked_passwords % 100 == 0:
                    total_estimated_checked = self.estimated_total_checked()
                    with self.log_lock:
                        print(f"Process {self.process_id}: {self.checked_passwords} passwords checked.\t{total_estimated_checked} passwords checked in total.\t Elapsed time: {time.time() - self.start_time:.3f}s. ")
                continue

            try:
                with self.log_lock:
                    print(f"Process {self.process_id}: \tPassword found: {password}")
                # with self.shared_dict.get_lock():
                self.shared_dict['found_password'] = password
                self.shared_dict['stop_execution'] = True
                return
            except Exception as e:
                raise e

def start_cracking_process(archive, dictionary, output, process_id, total_processes, max_passwords, log_lock, shared_dict):
    cracker = PasswordCracker(archive, dictionary, output, process_id, total_processes, max_passwords, log_lock, shared_dict)
    signal.signal(signal.SIGINT, cracker.handle_ctrlc)
    cracker.crack()

def parse_arguments():
    parser = ArgumentParser(description="Password Cracker for ZIP and 7z files.")
    parser.add_argument('-a', '--archive', required=True, type=str, help='Path to archive file')
    parser.add_argument('-d', '--dictionary', default='10m_common_passwords.txt', type=str, help='Path to password dictionary file')
    parser.add_argument('-o', '--output', required=True, type=str, help='Path for extracted files')
    parser.add_argument('-p', '--processes', default=8, type=int, help='Number of processes to split the task into')
    parser.add_argument('-m', '--max-passwords', default=1000, type=int, help='Maximum number of passwords to check')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()

    with open(args.dictionary, 'r') as file:
        total_passwords = sum(1 for _ in file)
    if args.max_passwords > total_passwords:
        print(f"Error: The specified max-passwords ({args.max_passwords}) exceeds the total number of passwords in the file ({total_passwords}).")
        sys.exit(1)

    total_processes = args.processes
    max_passwords = min(args.max_passwords, total_passwords)
    
    manager = Manager()
    shared_dict = manager.dict({'stop_execution': False})  # Shared dictionary for found password and stop flag
    log_lock = Lock()
    processes = []

    for i in range(total_processes):
        p = Process(target=start_cracking_process, args=(args.archive, args.dictionary, args.output, i, total_processes, max_passwords, log_lock, shared_dict))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    if 'found_password' in shared_dict:
        print(f"Password found: {shared_dict['found_password']}")
    else:
        print("Password not found.")
