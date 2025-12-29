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
        self.signature_file = signature_file
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def scan(self, directory):
        results = []
        
        #Scan all files recursively
        for root, _, files in os.walk(directory):
            for name in files:
                path = os.path.join(root, name)
                
                #Skip quarantined files
                if self.quarantine_dir in path:
                    continue
                
                #Use task A script to compare with database
                result = taskA_2.checkFile(path, self.signature_file) 

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
    results = scanner.scan(args.directory)
    
    #Print detected malicious files
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
