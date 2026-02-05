def read_log_file(file_name) ->list[list]:
    with open(file_name, "r") as f:
        r = f.readlines()
    matrix = []
    for row in r:
        new_row = row.split(",")
        new_row[-1] = new_row[-1].strip()
        matrix.append(new_row)
    return matrix

matrix = read_log_file("network_traffic.log")
for row in matrix:
    print(row)