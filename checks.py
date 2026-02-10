from reader import *


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
    count = sum(True for row in data if row[1] == source)
    return count

def dict_ip_requests(data:list[list])->dict:
    set_ip = set(row[1] for row in data)
    ip_requests = {ip: count_requests(data, ip) for ip in set_ip}
    return ip_requests

def match_port_to_protocols(data: list[list])->dict:
    dict_sorted = {row[3]: row[4] for row in data}
    return dict_sorted

def find_suspicions(row):
    arr_suspicions = []

    time = row[0].split(" ")[1][:2]
    if 0 <= int(time) <= 5:
        arr_suspicions.append("NIGHT_ACTIVITY")

    ip_address = row[1]
    if ip_address[:2] != "10" and ip_address[:7] != "192.168":
        arr_suspicions.append("EXTERNAL_IP")

    port = row[4]
    if port in ["22", "23", "3389"]:
        arr_suspicions.append("SENSITIVE_PORT")

    size = row[-1]
    if int(size) > 5000:
        arr_suspicions.append("LARGE_PACKET")

    return arr_suspicions

def suspicions_of_ips(data: list[list]) -> dict:
    dict_sus_ips = {}
    for row in data:
        ip = row[1]
        suspicions = find_suspicions(row)
        if suspicions:
            if ip not in dict_sus_ips:
                dict_sus_ips[ip] = suspicions
            elif suspicions != dict_sus_ips[ip]:
                dict_sus_ips[ip] = list(set(dict_sus_ips[ip] + suspicions))
    return dict_sus_ips


def ips_with_num_of_suspicions(suspicious_ips: dict) -> dict:
    susp_ips = {k: v for k, v in suspicious_ips.items() if len(v) >= 2}
    return susp_ips


#==============================================================================================================
#--------------------------------------stage3 ------- lambda, filter, map--------------------------------------
#==============================================================================================================


def get_times(data: list[list])->list[int]:
    """מקבל את כל הדאטה, רשימה של כל שורות הלוג, כל שורה כרשימה. ומחזיר רק את מספר השעה שההודעה נשלחה"""
    return list(map(lambda row: int(row[0].split(" ")[1][:2]), data))

def compress_bytes_to_kb(data:list[list]) -> list:
    return list(map(lambda size: round(int(size) / 1024,  2), (row[-1] for row in data)))

def find_sensitive_port(data:list[list])->list:
    return list(filter(lambda row: row[3] in ["22", "23", "3398"], data))

def find_night_activity(data:list[list])->list:
    return list(filter(lambda row: 0 <= int(row[0].split(" ")[1][:2]) < 6, data))

# # ------------------------------------------------------------
# # לשאלה 5
# # ------------------------------------------------------------

suspicion_checks = {
    "EXTERNAL_IP": lambda row: row[1][:2] != "10" and row[1][:7] != "192.168",
    "SENSITIVE_PORT": lambda row: row[3] in ["22", "23", "3389"],
    "LARGE_PACKET": lambda row: int(row[-1]) > 5000,
    "NIGHT_ACTIVITY": lambda row:  0 <= int(row[0].split(" ")[1][:2]) < 6
}

##6

def check_suspicious_row(row, dict_suspicions:dict):
    arr =  list(filter(lambda k: dict_suspicions[k](row), dict_suspicions))
    return arr

print(check_suspicious_row(mat[100], suspicion_checks))