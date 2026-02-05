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

row = outer_ips(mat)
for ip in row:
    print(ip)