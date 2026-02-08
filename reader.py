def read_log_file(file_name) ->list[list]:
    with open(file_name, "r") as f:
        r = f.readlines()
    matrix = [row.split(",") for row in r]
    return matrix

mat = read_log_file("network_traffic.log")
print(mat[0])

def outer_ips(data:list[list]):
    arr_ip = [row[1] for row in data if row[1][:2] != "10" and row[1][:7] != "192.168" ]
    return arr_ip

def suspected_ports(data:list[list]):
    suspected = [row for row in mat if row[3] in ("22", "23", "3389")]
    return suspected

def suspected_size(data:list[list]):
    suspected = [row for row in data if int(row[-1]) > 5000]
    return suspected

def labeled_by_size(data: list[list]):
    new_data = data.copy()
    labeled = [(row, "LARGE" if int(row[-1]) > 5000 else "NORMAL") for row in new_data]
    return labeled

labeled = labeled_by_size(mat)
for row in labeled:
    print(row)