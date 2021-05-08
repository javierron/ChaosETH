#!/usr/bin/python
# -*- coding: utf-8 -*-
# Filename: do_experiments.py

import os, sys, datetime, time, json, re, subprocess, signal, random
import argparse, configparser
import logging

INJECTOR = None

def handle_sigint(sig, frame):
    global INJECTOR
    if (INJECTOR != None): os.killpg(os.getpgid(INJECTOR.pid), signal.SIGTERM)
    exit()

def get_configs():
    parser = argparse.ArgumentParser(
        description="Conduct chaos engineering experiments on an ETH client")
    parser.add_argument("-c", "--config", required=True, help="the experiments config file (.ini)")
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.config)

    return config

def pgrep_the_client(client_name):
    try:
        pgrep_output = subprocess.check_output("pgrep ^%s$"%client_name, shell=True).decode("utf-8").strip()
    except subprocess.CalledProcessError as error:
        pgrep_output = None

    return pgrep_output

def restart_client(client_name, client_path, restart_cmd, client_log):
    os.system("cd %s && %s >> %s 2>&1 &"%(client_path, restart_cmd, client_log))
    time.sleep(3)

    pid = pgrep_the_client(client_name)
    if pid == None:
        logging.warning("failed to restart the client")
    else:
        logging.info("successfully restart the client, new pid: %s"%pid)

    return pid

def tail_client_log(client_log, timeout):
    try:
        output = subprocess.check_output("timeout %d tail -f %s"%(timeout, client_log), shell=True).decode("utf-8").strip()
    except subprocess.CalledProcessError as error:
        output = error.output.decode("utf-8").strip()

    return output

def dump_logs(content, filepath, filename):
    try:
        os.makedirs(filepath)
    except:
        pass
    with open(os.path.join(filepath, filename), 'wt') as log_file:
        log_file.write(content.encode("utf-8"))

def do_experiment(experiment, injector_path, client_name, client_log):
    global INJECTOR

    # experiment principle
    # 1 min normal execution, tail the log
    # 30 seconds error injection, tail the log
    #   restart hedwig if necessary
    # 5 min recovery phase, tail the log

    pid = pgrep_the_client(client_name)
    if pid == None:
        logging.warning("%s's pid is not detected!"%client_name)
        sys.exit(-1)
    logging.info("%s's pid detected: %s"%(client_name, pid))
    logging.info("begin the following experiment")
    logging.info(experiment)

    dump_logs_folder = "./%s/logs/%s%s-%s"%(client_name, experiment["syscall_name"], experiment["error_code"], experiment["failure_rate"])

    # step 1: 1 min normal execution, tail the log
    logging.info("1 min normal execution begins")
    normal_execution_log = tail_client_log(client_log, 60)
    dump_logs(normal_execution_log, dump_logs_folder, "normal.log")

    # step 2: error injection experiment
    result = dict()
    # start the injector
    logging.info("%d seconds chaos engineering experiment begins"%experiment["experiment_duration"])
    INJECTOR = subprocess.Popen("python -u %s -p %s -P %s --errorno=%s %s"%(
        injector_path, pid, experiment["failure_rate"], experiment["error_code"], experiment["syscall_name"]
    ), stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, shell=True, preexec_fn=os.setsid)
    ce_execution_log = tail_client_log(client_log, experiment["experiment_duration"])
    # end the injector
    os.killpg(os.getpgid(INJECTOR.pid), signal.SIGTERM)
    injector_stdout, injector_stderr = INJECTOR.communicate()
    INJECTOR = None
    pattern = re.compile(r'(\d+) failures have been injected so far')
    injection_count = pattern.findall(injector_stdout.decode("utf-8"))
    if len(injection_count) > 0:
        result["injection_count"] = int(injection_count[-1])
    else:
        logging.warning("something is wrong with the syscall_injector, injector's output:")
        logging.warning(injector_stdout.decode("utf-8"))
        logging.warning(injector_stderr.decode("utf-8"))
    dump_logs(ce_execution_log, dump_logs_folder, "ce.log")

    # check if the chaos engineering experiment breaks the client
    pid = pgrep_the_client(client_name)
    if pid == None:
        logging.info("this experiment makes the client crash!")
        result["client_crashed"] = True
    else:
        result["client_crashed"] = False

    # step 3: 5min recovery phase observation
    if not result["client_crashed"]:
        time.sleep(3)
        logging.info("5 min recovery phase observation begins")
        recovery_phase_log = tail_client_log(client_log, 60*5)
        dump_logs(recovery_phase_log, dump_logs_folder, "recovery.log")

    logging.info(result)
    experiment["result"] = result
    return experiment

def save_experiment_result(experiments, filename):
    with open(filename, "wt") as output:
        json.dump(experiments, output, indent = 2)

def main(config):
    global INJECTOR

    error_models = config["ChaosEVM"]["error_models"]
    syscall_injector = config["ChaosEVM"]["syscall_injector"]
    client_name = config["EthClient"]["client_name"]
    client_path = config["EthClient"]["client_path"]
    restart_cmd = config["EthClient"]["restart_cmd"]
    client_log = config["EthClient"]["client_log"]

    with open(error_models, 'rt') as file:
        experiments = json.load(file)

        for experiment in experiments["experiments"]:
            experiment = do_experiment(experiment, syscall_injector, client_name, client_log)
            save_experiment_result(experiments, "%s-results.json"%client_name)
            if experiment["result"]["client_crashed"]:
                new_pid = restart_client(client_name, client_path, restart_cmd, client_log)
                if new_pid == None: break
            time.sleep(5)

    if (INJECTOR != None): os.killpg(os.getpgid(INJECTOR.pid), signal.SIGTERM)

if __name__ == "__main__":
    logger_format = '%(asctime)-15s %(levelname)-8s %(message)s'
    logging.basicConfig(level=logging.INFO, format=logger_format)
    signal.signal(signal.SIGINT, handle_sigint)

    config = get_configs()
    main(config)