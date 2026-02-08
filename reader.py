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

#==============================================================================================================
#------------------------------------------stage2 ------- dict_comprehension-----------------------------------
#==============================================================================================================

def count_requests(data:list[list], source:str)->int:
    arr = [True for row in data if row[1] == source]
    return len(arr)

def dict_IP_requests(data:list[list])->dict:
    IP_requests = {row[1]: count_requests(data, row[1]) for row in data}
    return IP_requests

ip_req = dict_IP_requests(mat)
for key, val in ip_req.items():
    print(f"[{key} --> {val}]")