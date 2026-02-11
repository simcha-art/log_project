import analyzer
import checks

def generate_report(suspicious_dict:dict):
    message = "=======================================\n"
    message += "           דוח תעבורה חשודה            \n"
    message += "=======================================\n\n"
    message += "סטטיסטיקות כלליות:\n"
    message += f"שורות שנקראו: {checks.num_read_lines}\n"
    message += f"שורות חשודות: {checks.num_susp_lines}\n"
    message += f"EXTERNAL_IP: {checks.ip_sus}\n"
    message += f"SENSITIVE_PORT: {checks.port_sus}\n"
    message += f"LARGE_PACKET: {checks.size_sus}\n"
    message += f"NIGHT_ACTIVITY: {checks.time_sus}\n\n"

    highly_dangerous = []
    others = []
    for ip, susps in suspicious_dict.items():
        if len(susps) >= 3:
            highly_dangerous.append((ip, susps))
        else:
            others.append((ip, susps))

    message += f"IPs עם רמת סיכון גבוהה (3+ חשדות):\n"
    for item in highly_dangerous:
        ip = item[0]
        susp = item[1]
        message += f"- {ip} :"
        for s in susp:
            message += f" {s},"
        message = message[:-1]
        message += "\n"
    message += "\n"

    message += f"IPs חשודים נוספים:\n"
    for item in highly_dangerous:
        ip = item[0]
        susp = item[1]
        message += f"- {ip} :"
        for s in susp:
            message += f" {s},"
        message = message[:-1]
        message += "\n"

    return message




report1 = generate_report(analyzer.analyze_log("network_traffic.log"))

def save_report(report, file_path):
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(report)

save_report(report1, "report.txt")