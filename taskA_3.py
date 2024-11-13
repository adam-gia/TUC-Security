import hashlib

def calculate_hashes(filename):
    
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    sha1 = hashlib.sha1()

    with open(filename, "rb") as file:

        while chunk := file.read(1024):
            sha256.update(chunk)
            sha512.update(chunk)
            sha1.update(chunk)

    sha1_hash = sha1.hexdigest()
    sha256_hash = sha256.hexdigest()
    sha512_hash = sha512.hexdigest()

    print(f"{sha1_hash}\n{sha256_hash}\n{sha512_hash}\n")

calculate_hashes("1.pdf")
calculate_hashes("2.pdf")
calculate_hashes("3.pdf")
calculate_hashes("4.pdf")
calculate_hashes("5.pdf")
#calculate_hashes("6.pdf")
#calculate_hashes("7.pdf")
calculate_hashes("8.pdf")
calculate_hashes("9.pdf")
calculate_hashes("10.pdf")
