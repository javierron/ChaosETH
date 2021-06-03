#!/usr/bin/python
# -*- coding: utf-8 -*-
# Filename: do_experiments.py

import os, sys, requests, datetime, time, json, re, subprocess, signal, random, numpy
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

def query_peer_stats(client_name, query_url, last_n_seconds):
    end_ts = int(time.time())
    start_ts = end_ts - last_n_seconds
    response = requests.get(query_url.format(start=start_ts, end=end_ts))
    results = None

    if client_name == "openethereum":
        status = response.json()["status"]
        if status == "error":
            logging.error("peer stats query failed")
            logging.error(response.json())
        else:
            if len(response.json()['data']['result']) == 0:
                logging.warning("peer stats query result is empty")
            else:
                results = response.json()['data']['result'][0]
    elif client_name == "geth":
        if "results" not in response.json():
            logging.error("peer stats query failed")
            logging.error(response.json())
        else:
            results = response.json()["results"][0]["series"][0]

    # calculate statistic information of the values
    if results != None:
        values = numpy.array(results["values"]).astype(int)
        min_value = numpy.percentile(values, 5, axis=0)[1] # in the values array, index 0: timestamp, index 1: failure rate
        mean_value = numpy.mean(values, axis=0)[1]
        max_value = numpy.percentile(values, 95, axis=0)[1]
        variance = numpy.var(values, axis=0)[1]
        results["stat"] = {"min": min_value, "mean": mean_value, "max": max_value, "variance": variance}

    return results

def dump_logs(content, filepath, filename):
    try:
        os.makedirs(filepath)
    except:
        pass
    with open(os.path.join(filepath, filename), 'wt') as log_file:
        log_file.write(content.encode("utf-8"))

def dump_metric(content, filepath, filename):
    try:
        os.makedirs(filepath)
    except:
        pass
    with open(os.path.join(filepath, filename), "wt") as output:
        json.dump(content, output, indent = 2)

def do_experiment(experiment, injector_path, client_name, client_log, dump_logs_path, peer_stats_url):
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

    dump_logs_folder = "%s/%s%s-%s"%(dump_logs_path, experiment["syscall_name"], experiment["error_code"], experiment["failure_rate"])

    result = dict()
    # step 1: 5 mins normal execution, tail the log
    logging.info("5 min normal execution begins")
    normal_execution_log = tail_client_log(client_log, 60*5)
    dump_logs(normal_execution_log, dump_logs_folder, "normal.log")
    normal_execution_peer_stat = query_peer_stats(client_name, peer_stats_url, 60*5)
    dump_metric(normal_execution_peer_stat, dump_logs_folder, "normal_peer_stat.json")
    result["peer_stat"] = dict()
    result["peer_stat"]["normal"] = normal_execution_peer_stat["stat"]

    # step 2: error injection experiment
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
        # only query peer stats when the client is not crashed
        ce_execution_peer_stat = query_peer_stats(client_name, peer_stats_url, experiment["experiment_duration"])
        dump_metric(ce_execution_peer_stat, dump_logs_folder, "ce_peer_stat.json")
        result["peer_stat"]["ce"] = ce_execution_peer_stat["stat"]

    # step 3: 5 mins recovery phase observation
    if not result["client_crashed"]:
        time.sleep(3)
        logging.info("5 min recovery phase observation begins")
        recovery_phase_log = tail_client_log(client_log, 60*5)
        dump_logs(recovery_phase_log, dump_logs_folder, "recovery.log")
        recovery_phase_peer_stat = query_peer_stats(client_name, peer_stats_url, 60*5)
        dump_metric(recovery_phase_peer_stat, dump_logs_folder, "recovery_peer_stat.json")
        result["peer_stat"]["recovery"] = recovery_phase_peer_stat["stat"]

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
    dump_logs_path = config["ChaosEVM"]["dump_logs_path"]
    client_name = config["EthClient"]["client_name"]
    client_path = config["EthClient"]["client_path"]
    restart_cmd = config["EthClient"]["restart_cmd"]
    client_log = config["EthClient"]["client_log"]
    peer_stats_url = config["EthClient"]["peer_stats_url"]

    with open(error_models, 'rt') as file:
        experiments = json.load(file)

        for experiment in experiments["experiments"]:
            experiment = do_experiment(experiment, syscall_injector, client_name, client_log, dump_logs_path, peer_stats_url)
            save_experiment_result(experiments, "%s-results.json"%client_name)
            if experiment["result"]["client_crashed"]:
                new_pid = restart_client(client_name, client_path, restart_cmd, client_log)
                if new_pid == None: break
                # sleep for another 5 mins here if the client crashed due to the previous experiment
                # this helps the client to warm up before a new experiment
                time.sleep(60*5)
            time.sleep(5)

    if (INJECTOR != None): os.killpg(os.getpgid(INJECTOR.pid), signal.SIGTERM)

if __name__ == "__main__":
    logger_format = '%(asctime)-15s %(levelname)-8s %(message)s'
    logging.basicConfig(level=logging.INFO, format=logger_format)
    signal.signal(signal.SIGINT, handle_sigint)

    config = get_configs()
    main(config)