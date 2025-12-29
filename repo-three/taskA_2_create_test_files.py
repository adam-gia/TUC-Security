import hashlib, os, random, argparse

def create_test_malware(string, filename, directory):

    os.makedirs(directory, exist_ok=True)

    filepath = os.path.join(directory, filename)

    with open(filepath, "w") as file:
        file.write(f"{string}")

        print(hashlib.md5(string.encode()).hexdigest())

def generate_test_files():

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory')

    args = parser.parse_args()

    if args.directory:
        directory = args.directory
    else:
        directory = "test"


    for i in range(5):
        create_test_malware("malware"+str(i), "malware"+str(i), directory)

    for i in range(5):
        create_test_malware("nonmalware"+str(i), "notmalware"+str(i), directory)
    
    for i in range(5):
        create_test_malware(os.urandom(random.randint(1, 128)).hex(), "random"+str(i), directory)

    print("Files generated!")

generate_test_files()