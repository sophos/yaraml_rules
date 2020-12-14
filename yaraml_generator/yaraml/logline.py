from datetime import datetime

def log(line):
    now = datetime.now()
    dt_string = now.strftime("%m/%d/%Y %H:%M:%S")
    print("[*]",dt_string,line)


