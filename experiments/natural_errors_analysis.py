#!/usr/bin/python
# -*- coding: utf-8 -*-
# Filename: natural_errors_analysis.py

import os, time, argparse, subprocess, signal

import logging

MONITOR = None
DRETESTETH = None

def handle_sigint(sig, frame):
    global MONITOR
    global DRETESTETH
    if (MONITOR != None): os.killpg(os.getpgid(MONITOR.pid), signal.SIGTERM)
    if (DRETESTETH != None): os.killpg(os.getpgid(DRETESTETH.pid), signal.SIGTERM)
    exit()

def handle_args():
    parser = argparse.ArgumentParser(
        description="Observe natural errors in EVM using its test cases")
    parser.add_argument("-m", "--monitor", required=True, help="path to syscall_monitor.py")
    parser.add_argument("-t", "--testpath", required=True, help="path to the root folder of eth tests")
    parser.add_argument("-c", "--testcategory", default="GeneralStateTests", help="the main category of tests")
    parser.add_argument("-e", "--dretesteth", required=True, help="path to dretesteth.sh")
    return parser.parse_args()

def extract_test_folders(test_path, test_category):
    folders = list()
    for file in os.listdir(os.path.join(test_path, test_category)):
        if os.path.isdir(os.path.join(test_path, test_category, file)):
            folders.append("%s/%s"%(test_category, file))
    return folders

def main(args):
    global MONITOR
    global DRETESTETH

    test_folders = extract_test_folders(args.testpath, args.testcategory)

    for sub_tests in test_folders:
        logging.info("Run tests in folder %s"%sub_tests)
        MONITOR = subprocess.Popen("%s --process evm -mL -i 15 >/dev/null 2>&1"%args.monitor, close_fds=True, shell=True, preexec_fn=os.setsid)

        run_tests_cmd = "%s -t %s -- --testpath %s --datadir /tests/config --clients local >> dretesteth.log 2>&1"%(args.dretesteth, sub_tests, args.testpath)
        DRETESTETH = subprocess.Popen(run_tests_cmd, close_fds=True, shell=True, preexec_fn=os.setsid)
        exit_code = DRETESTETH.wait()
        DRETESTETH = None
        time.sleep(15)

        if (MONITOR != None):
            os.killpg(os.getpgid(MONITOR.pid), signal.SIGTERM)
            MONITOR = None
        time.sleep(1)
        logging.info("Done, exit code of dretesteth.sh: %d"%exit_code)

    if (MONITOR != None): os.killpg(os.getpgid(MONITOR.pid), signal.SIGTERM)
    if (DRETESTETH != None): os.killpg(os.getpgid(DRETESTETH.pid), signal.SIGTERM)

if __name__ == "__main__":
    logger_format = '%(asctime)-15s %(levelname)-8s %(message)s'
    logging.basicConfig(level=logging.INFO, format=logger_format)
    signal.signal(signal.SIGINT, handle_sigint)

    args = handle_args()
    main(args)