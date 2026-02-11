

def read_log_file(file_name):
    with open(file_name, "r") as f:
        for line in f:
            yield line.split(",")

