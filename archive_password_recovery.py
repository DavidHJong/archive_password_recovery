import time
import signal
import sys
from argparse import ArgumentParser
from zipfile import ZipFile
import py7zr

# Set a higher recursion limit (if needed)
sys.setrecursionlimit(999999999)

class PasswordCracker:
    def __init__(self, archive, dictionary, output):
        self.archive = archive
        self.dictionary = dictionary
        self.output = output
        self.stop_execution = False

    def handle_ctrlc(self, signal, frame):
        """Gracefully exit the current operation when Ctrl+C is pressed."""
        self.stop_execution = True
        print("\nUser cancelled operation.")

    def crack(self):
        if self.archive.endswith(".7z"):
            self._crack_7z()
        elif self.archive.endswith('.zip'):
            self._crack_zip()

    def _crack_7z(self):
        self._crack_archive(py7zr.SevenZipFile)

    def _crack_zip(self):
        self._crack_archive(ZipFile, encode_password=True)

    def _crack_archive(self, archive_class, encode_password=False):
        count = 0
        with open(self.dictionary, 'r') as f:
            lines = f.read().splitlines()

        start_time = time.time()
        for line in lines:
            if self.stop_execution:
                break
            try:
                with archive_class(self.archive, mode='r', password=line.encode("utf-8") if encode_password else line) as archive:
                    archive.extractall(self.output)
                    self._print_success(line, start_time, count)
                    break
            except Exception as e:
                count += 1
                if count % 10 == 0:
                    print(count, line)

    def _print_success(self, password, start_time, count):
        print("===========================================")
        print("Status: Cracked")
        print(f'Password: {password}')
        print(f"Time: {time.time() - start_time} seconds")
        print(f'{count} passwords checked')
        print("===========================================")

def parse_arguments():
    parser = ArgumentParser(description="Password Cracker for ZIP and 7z files.")
    parser.add_argument('-a', '--archive', required=True, type=str, help='Path to archive file')
    parser.add_argument('-d', '--dictionary', required=True, type=str, help='Path to password dictionary file')
    parser.add_argument('-o', '--output', required=True, type=str, help='Path for extracted files')
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_arguments()

    cracker = PasswordCracker(args.archive, args.dictionary, args.output)
    signal.signal(signal.SIGINT, cracker.handle_ctrlc)
    cracker.crack()
