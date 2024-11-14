# Malware Detection Tool

## Contributors    
- **Name** Adam Giaourtas 
    - **AM** 2019030106
- **Name** Alexandros Goridaris 
    - **AM** 2019030108

## Overview
This is a malware detection tool created in Python. It performes signature-based scanning, dynamic hashing comparisons, file monitoring and quarantine functions.

## Project Files

- **taskA_create_test_files.py**: Generates 15 test files. These include: 
    - 5 files with know malware signatures, 
    - 5 non-malware files, and 
    - 5 random files.
- **taskA_2.py**: Compares the md5 and SHA256 hashes of a file against the `malware_signatures.txt` database to identify potential malware. 
- **taskA_3.py**: Calculates SHA1, SHA256, SHA512 hashes of given pdf files.
- **taskB.py**: Scans a directory recursively, isolates suspicious files and logs results.
- **taskC.py**: Provides real-time malware detection and quarantine of recently created or modified files.
- **malware-detect.py**: Combines created scripts into a malware detection tool.

## Malware Signatures File

A `malware_signatures.txt` file was created, containing 50 entries randomly labeled as either one of several types of malware or clean. Each entry includes:
- MD5 and SHA256 hashes, 
- Malware type, 
- Infection date, and 
- Severity level.  

Some hashes are specificaly chosen in order to be tested using the test files of task A.

## Tool Specification

The tool accespts the following command-line arguements:
- `-d <directory>`: The directory to scan.
- `-s <signature_file>`: Path to the malware signature database.
- `-o <output_file>`: File to save a report of infected files.
- `-r` (optional): Run in real-time mode to monitor the directory. 
 
## Setup and Usage

### Test file creation
- Use `taskA_create_test_files.py` to generate the test files.
#### Arguements
- `-d <directory>` (optional): Specify the directory where test files will be created. The default directory is `test`
```bash
python3 taskA_create_test_files.py [-d <directory>]
```
### Malware Detection
- Use `malware-detect.py` with the specified arguments to utilize the tool.

```bash
python3 malware-detect.py -d <directory> -s malware_signatures.txt -o <output_file> [-r]
```
## A3. Multi-hash Validation
After calculating and performing pairwise comparisons of the hashes for the given pdf files, 
it was observed that each hash is unique, not only across different files but also across each hash 
type for the same file. This could be benefitial in malware detection, as it ensures more accurate
identification of malicious files and reduces the risk of hash collisions by utilizing multiple hash
algorithms.
