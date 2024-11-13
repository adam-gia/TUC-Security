import argparse
import os
import taskB
import taskA_2
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEvent, FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent

class EventHandler(FileSystemEventHandler):

    def __init__(self, signature_file, output_file):
        self.signature_file = signature_file
        self.output_file = output_file

    def on_created(self, event):
        if isinstance(event, FileCreatedEvent):
            file = event.src_path
            print(f"File Created: {file}")
            detectMalware(file, self.signature_file, self.output_file)

    def on_deleted(self, event):
        if isinstance(event, FileDeletedEvent):
            file = event.src_path
            print(f"File Deleted: {file}")


    def on_modified(self, event):
        if isinstance(event, FileModifiedEvent):
            file = event.src_path
            print(f"File Modified: {file}")
            detectMalware(file, self.signature_file, self.output_file)

def detectMalware(file, signature_file, output_file):
    result = taskA_2.checkFile(file, signature_file)
    if(result['type']):    
        rtype = result['type']
        print(f"File type: {rtype}")

        if(rtype != "Clean" and rtype != None):
            taskB.quarantineFile(file, "quarantine", result, output_file)

def start_real_time(directory, signature_file, output_file):
    event_handler = EventHandler(signature_file, output_file)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    print(f"Monitoring directory {directory}")

    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', required=True)
    parser.add_argument('-s', '--signature-file', required=True)
    parser.add_argument('-o', '--output-file')
    args = parser.parse_args()

    start_real_time(args.directory ,args.signature_file, args.output_file)

if __name__ == '__main__':
    main()
