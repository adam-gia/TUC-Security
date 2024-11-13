import hashlib
import os
from datetime import datetime

def checkFile(filename, malware_database):
    
    result = {
        'path': filename,
        'md5': None,
        'sha256': None,
        'size': 0,
        'date': datetime.now().strftime("%Y:%m:%d"),
        'malicious': False,
        'type': None,
        'level': 'Clean'
    }

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    
    try:
        with open(filename, "rb") as file:

            while chunk := file.read(1024):
                md5.update(chunk)
                sha256.update(chunk)

        md5_hash = md5.hexdigest()
        sha256_hash = sha256.hexdigest()

        result.update({
            'md5' : md5_hash,
            'sha256' : sha256_hash,
            'size' : os.path.getsize(filename)
        })

    except FileNotFoundError:
        print("File not found!")
        return result
    except PermissionError:
        print("Could not access file!")
        return result
    except IOError as e:
        print(f"I/O Exception: {e}")
        return result

    with open(malware_database, "r") as database:

        for line in database:
            next(database); next(database)  #Skip headers
            for line in database:
                if line.strip():
                    parts = line.split(' ')
                    md5_db = parts[0].strip()
                    sha256_db = parts[1].strip()
                    malware_type = parts[2].strip()
                    date = parts[3].strip()
                    level = parts[4].strip()
            
                    if md5_db == md5_hash and sha256_db == sha256_hash:
                        #print(f"{malware_type}")
                        if malware_type != "Clean":
                            result.update({
                            'malicious': True,
                            'type' : malware_type,
                            'level' : level,
                            'date' : date
                            })
                            return result
                        else:
                            result.update({
                            'type' : malware_type,
                            'date' : date
                            })
                            
                            return result           
            
    print(f"File {filename} not in database")
    return result

def main():
    
    for i in range(5):
        result = checkFile("malware"+str(i), "malware_signatures3.txt")
        print(f"File: {result['path']} Type: {result['type']}")
    for i in range(5):
        result = checkFile("notmalware"+str(i), "malware_signatures3.txt")
        print(f"File: {result['path']} Type: {result['type']}")
    for i in range(5):
        result = checkFile("random"+str(i), "malware_signatures3.txt")
        print(f"File: {result['path']} Type: {result['type']}")


if __name__ == '__main__':
    main()