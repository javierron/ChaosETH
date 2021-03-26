#!/usr/bin/python
# -*- coding: utf-8 -*-
# Filename: do_experiments.py

import os, time, argparse, subprocess, tempfile, signal
import csv, re
import logging

INJECTOR = None
DRETESTETH = None

def handle_sigint(sig, frame):
    global INJECTOR
    global DRETESTETH
    if (INJECTOR != None): os.killpg(os.getpgid(INJECTOR.pid), signal.SIGTERM)
    if (DRETESTETH != None): os.killpg(os.getpgid(DRETESTETH.pid), signal.SIGTERM)
    exit()

def handle_args():
    parser = argparse.ArgumentParser(
        description="Observe natural errors in EVM using its test cases")
    parser.add_argument("-i", "--injector", required=True, help="the path to syscall_injector.py")
    parser.add_argument("-c", "--config", required=True, help="the fault injection config (.csv)")
    parser.add_argument("-t", "--testpath", required=True, help="path to the root folder of eth tests")
    parser.add_argument("--testcategory", default="GeneralStateTests", help="the main category of tests")
    parser.add_argument("-e", "--dretesteth", required=True, help="path to dretesteth.sh")
    return parser.parse_args()

# return (headers, rows)
def read_from_csv(path):
    with open(path) as f:
        f_csv = csv.DictReader(f)
        return f_csv.fieldnames, list(f_csv)

def write_to_csv(path, headers, rows):
    with open(path, 'w', newline='') as file:
        f_csv = csv.DictWriter(file, headers)
        f_csv.writeheader()
        f_csv.writerows(rows)

def log_to_file(path, content):
    with open(path, "a") as log_file:
        log_file.writelines(content)

def do_experiment(config, dretesteth, testpath, test_folders, injector):
    global INJECTOR
    global DRETESTETH

    logging.info("experiment begins!")
    logging.info("system call: %s, error code: %s, error rate: %s"%(config["system_call"], config["error_code"], config["error_rate"]))
    result = {"success": 0, "failure": 0, "timeout": 0, "injection_count": 0}
    for sub_tests in test_folders:
        logging.info("run tests in folder %s"%sub_tests)
        INJECTOR = subprocess.Popen("/usr/bin/python -u %s --process evm -P %s --errorno=-%s %s"%(
            injector, config["error_rate"], config["error_code"], config["system_call"]
        ), stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, shell=True, preexec_fn=os.setsid)
        time.sleep(3)

        run_tests_cmd = "%s -t %s -- --testpath %s --datadir /tests/config --clients local"%(dretesteth, sub_tests, testpath)
        with tempfile.NamedTemporaryFile(mode="w+b") as f_output:
            DRETESTETH = subprocess.Popen(run_tests_cmd, stdout=f_output.fileno(), stderr=f_output.fileno(), close_fds=True, shell=True, preexec_fn=os.setsid)
            try:
                timeout_flag = False
                exit_code = DRETESTETH.wait(timeout=300)
            except subprocess.TimeoutExpired as err:
                os.killpg(os.getpgid(DRETESTETH.pid), signal.SIGTERM)
                exit_code = "-999"
                timeout_flag = True
                result["timeout"] = result["timeout"] + 1
                log_to_file("./logs/dretesteth-%s-%s-%s.log"%(config["system_call"], config["error_code"], config["error_rate"]), "Timeout when executing %s\n"%sub_tests)
                logging.info("Timeout when executing %s\n"%sub_tests)
            DRETESTETH = None
            f_output.flush()
            f_output.seek(0, os.SEEK_SET)
            test_output = f_output.read().decode("utf-8")
            log_to_file("./logs/dretesteth-%s-%s-%s.log"%(config["system_call"], config["error_code"], config["error_rate"]), test_output)

        # analyze the test results
        pattern_success = re.compile(r'Total Tests Run: (\d+)')
        pattern_failure = re.compile(r'TOTAL ERRORS DETECTED: (\d+)')
        match = pattern_success.search(test_output)
        success_count = int(match.group(1)) if match else 0
        match = pattern_failure.search(test_output)
        failure_count = int(match.group(1)) if match else 0
        result["success"] = result["success"] + success_count
        result["failure"] = result["failure"] + failure_count

        time.sleep(3)

        # end the injector
        os.killpg(os.getpgid(INJECTOR.pid), signal.SIGTERM)
        injector_stdout, injector_stderr = INJECTOR.communicate()
        INJECTOR = None
        pattern = re.compile(r'(\d+) failures have been injected so far')
        injection_count = pattern.findall(injector_stdout.decode("utf-8"))
        if len(injection_count) > 0:
            injection_count = int(injection_count[-1])
            result["injection_count"] = result["injection_count"] + injection_count
        else:
            injection_count = -1
            logging.warning("something is wrong with the syscall_injector, injector's output:")
            logging.warning(injector_stdout)
            logging.warning(injector_stderr)

        logging.info("Done, exit code of dretesteth.sh: %d, success: %d, failure: %d, timeout: %s, injection_count: %d"%(exit_code, success_count, failure_count, timeout_flag, injection_count))

    logging.info("experiment ends!")

    if (INJECTOR != None): os.killpg(os.getpgid(INJECTOR.pid), signal.SIGTERM)
    if (DRETESTETH != None): os.killpg(os.getpgid(DRETESTETH.pid), signal.SIGTERM)

    return result

def extract_test_folders(test_path, test_category):
    folders = list()
    for file in os.listdir(os.path.join(test_path, test_category)):
        if os.path.isdir(os.path.join(test_path, test_category, file)):
            folders.append("%s/%s"%(test_category, file))
    return folders

def main(args):
    headers, configs = read_from_csv(args.config)
    if "success" not in headers: headers.extend(["success", "failure", "timeout", "injection_count"])

    test_folders = extract_test_folders(args.testpath, args.testcategory)

    # create a folder to save log files
    if not os.path.isdir("./logs"): os.system("mkdir ./logs")
    for config in configs:
        result = do_experiment(config, args.dretesteth, args.testpath, test_folders, args.injector)
        config["success"] = result["success"]
        config["failure"] = result["failure"]
        config["timeout"] = result["timeout"]
        config["injection_count"] = result["injection_count"]
        write_to_csv(args.config, headers, configs)

if __name__ == "__main__":
    logger_format = '%(asctime)-15s %(levelname)-8s %(message)s'
    logging.basicConfig(level=logging.INFO, format=logger_format)
    signal.signal(signal.SIGINT, handle_sigint)

    args = handle_args()
    main(args)