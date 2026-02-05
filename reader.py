def read_log_file(file_name) ->list[list]:
    with open(file_name, "r") as f:
        r = f.readlines()
    matrix = [row.split(",") for row in r]
    return matrix

mat = read_log_file("network_traffic.log")
for row in mat:
    print(row)