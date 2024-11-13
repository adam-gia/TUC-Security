import os
import hashlib
import shutil
import logging
import json
import argparse
from datetime import datetime
import taskA_2

class MalwareScanner:
    def __init__(self, signature_file, output_file):
        self.quarantine_dir = "quarantine"
        self.outfile = output_file
        os.makedirs(self.quarantine_dir, exist_ok=True)

        #Basic logging setup
        

    def hash_file(self, path):
        #Get file hashes
        h1, h2 = hashlib.md5(), hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                buf = f.read(8192)
                while buf:
                    h1.update(buf)
                    h2.update(buf)
                    buf = f.read(8192)
            return h1.hexdigest(), h2.hexdigest()
        except:
            return None, None

    def scan(self, directory, signature_file):
        results = []
        
        #Scan all files recursively
        for root, _, files in os.walk(directory):
            for name in files:
                path = os.path.join(root, name)
                
                #Skip quarantined files
                if self.quarantine_dir in path:
                    continue

                #Get file info
                md5, sha256 = self.hash_file(path)
                if not md5:
                    continue

                result = taskA_2.checkFile(path, signature_file)

                if(result['malicious']):
                    #Quarantine bad files
                    quarantineFile(path, self.quarantine_dir, result, self.outfile)

                results.append(result)

        return results

def quarantineFile(filepath, quarantine_path, info, outfile):

    logging.basicConfig(filename=outfile, level=logging.INFO,
                          format='%(asctime)s - %(levelname)s - %(message)s')

    name = os.path.basename(filepath)
    try:
        new_path = os.path.join(quarantine_path, f"{name}")
        shutil.move(filepath, new_path)
        logging.warning(f"Quarantined {filepath} MD5:{info['md5']} SHA256:{info['sha256']} Size:{info['size']} bytes Date:{info['date']} Type:{info['type']} Level:{info['level']}")
    except:
        logging.error(f"Failed to quarantine {filepath}")

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', required=True)
    parser.add_argument('-s', '--signature-file', required=True)
    parser.add_argument('-o', '--output-file')
    args = parser.parse_args()

    if args.output_file:
        outfile = args.output_file
    else:
        outfile = "report.log"

    #Run scan and show results
    scanner = MalwareScanner(args.signature_file, outfile)
    results = scanner.scan(args.directory, args.signature_file)
    
    bad = [r for r in results if r['malicious']]
    print(f"\nScanned {len(results)} files")
    print(f"Found {len(bad)} threats")

    if bad:
        print("\nThreats found:")
        for b in bad:
            print(f"\nFile: {b['path']}")
            print(f"Type: {b['type']}")
            print(f"Level: {b['level']}")
            print(f"Date: {b['date']}")

if __name__ == '__main__':
    main()
