import hashlib, os, random

def create_test_malware(string, filename):

    with open(filename, "w") as file:
        file.write(f"{string}")

        print(hashlib.md5(string.encode()).hexdigest())

def generate_test_files():

    for i in range(5):
        create_test_malware("malware"+str(i), "malware"+str(i))

    for i in range(5):
        create_test_malware("nonmalware"+str(i), "notmalware"+str(i))
    
    for i in range(5):
        create_test_malware(os.urandom(random.randint(1, 128)).hex(), "random"+str(i))

    print("Files generated!")

generate_test_files()