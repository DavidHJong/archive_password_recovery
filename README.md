
# 🔐 Archive Password Recovery

🔑 A Python tool for recovering ZIP and 7z archive passwords using parallel processing

## Disclaimer
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Requirements
+ zipfile
+ argparse
+ py7zr
+ multiprocessing
+ signal

## Features
- Include a commonly used password dictionary. 
- Parallel processing: Distribute the password recovering process across multiple CPU cores.
- Performance logging to monitor the progress of password recovering.

## Installation and Usage
### Clone the repository
```
git clone https://github.com/DavidHJong/archive_password_recover.git
```
### Navigate to the project directory
```
cd [Your Downloaded Project Directory]
```
### Install required dependencies
```
pip install -r requirements.txt
```
### Run the script with command-line arguments
```
python archive_password_recover_parallel.py -a <archive> -d <dictionary> -o <output> -p <processes> -m <max-passwords>
```

### Command-line Arguments
- `-h, --help`: Show help message and exit.
- `-a <archive>, --archive <archive>`: Path to the archive file (zip or 7z).
- `-d <dictionary>, --dictionary <dictionary>`: Path to the password dictionary file.
- `-o <output>, --output <output>`: Path for extracted files.
- `-p <processes>, --processes <processes>`: Specify the number of parallel processes (default is 8).
- `-m <max-passwords>, --max-passwords <max-passwords>`: Set the maximum number of passwords to check (default is 1000).

## Contributing
Contributions to this project are welcome. Please create a pull request with your proposed changes.
