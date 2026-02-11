from reader import *
from checks import *

num_read_lines = 0
num_susp_lines = 0

time_sus = 0
port_sus = 0
ip_sus = 0
size_sus = 0

def update_count(new_line:bool= False, is_sus_line:bool= False, is_time_sus:bool= False, is_port_sus:bool= False, is_ip_sus:bool= False, is_size_sus:bool = False):
    global num_read_lines, num_susp_lines, time_sus, port_sus, ip_sus, size_sus
    num_read_lines += 1 if new_line else 0
    if is_sus_line:
        num_susp_lines += 1
        time_sus += 1 if is_time_sus else 0
        port_sus += 1 if is_port_sus else 0
        ip_sus += 1 if is_ip_sus else 0
        size_sus += 1 if is_size_sus else 0

