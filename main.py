import checks
import reader
import analyzer
import reporter

def main():
    #קריאה וניתוח
    suspicious = analyzer.analyze_log("network_traffic.log")

    #דיווח
    report = reporter.generate_report(suspicious)

    #הדפסת דיווח
    print(report)

    #שמירה לקובץ
    reporter.save_report(report, "report.txt")

if __name__ == "__main__":
    main()

