##======================================================================================================================
##----------------------------------------------stage5---------integration----------------------------------------------
##======================================================================================================================


from reader import *
import checks


def turn_to_dict(susp_lines):
    dic_susp_ips = {}
    for tup in susp_lines:
        ip = tup[0]
        susp = tup[1]
        if ip not in dic_susp_ips:
            dic_susp_ips[ip] = susp
        else:
            dic_susp_ips[ip] = set(susp + list(dic_susp_ips[ip]))
    return dic_susp_ips

def analyze_log(file_path):
    lines = read_log_file(file_path)
    suspicious = checks.check_suspicions_log(lines)
    detailed = turn_to_dict(checks.tuple_line_suspicions(lines))
    for v in detailed.values():
        is_ip = True if "EXTERNAL_IP" in v else False
        is_time = True if "NIGHT_ACTIVITY" in v else False
        is_port = True if "SENSITIVE_PORT" in v else False
        is_size = True if "LARGE_PACKET" in v else False
        checks.update_count(False, False, is_time, is_port, is_ip, is_size)
    return detailed

# details = analyze_log("network_traffic.log")

# for k, v in details.items():
#     print(f"{k} ---->>> {v}")

# print(checks.num_read_lines)
# print(checks.num_susp_lines)
# print(checks.size_sus)
# print(checks.ip_sus)
# print(checks.port_sus)
# print(checks.time_sus)

