#!/usr/bin/python
# -*- coding: utf-8 -*-
# Filename: results_to_latex.py

import os, sys, argparse, json, math, csv
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import ks_2samp
import logging

TEMPLATE_CE_RESULTS = r"""\begin{table}[tb]
\scriptsize
\centering
\caption{Chaos Engineering Experiment Results on %s}\label{tab:ce-experiment-results-%s}
\begin{tabularx}{\columnwidth}{lrrrXX}
\toprule
\textbf{System Call}& \textbf{Error Code}& \textbf{E. R.}& \textbf{Inj.}& \textbf{H\textsubscript{C}}& \textbf{H\textsubscript{R}} \\
\midrule
""" + "%s" + r"""
\bottomrule
\multicolumn{6}{p{8.5cm}}{
H\textsubscript{C}: Marked if the injected errors crash the client.\newline
H\textsubscript{R}: Marked if the client can recover to its steady state after the error injection stops.}
\end{tabularx}
\end{table}
"""

def get_args():
    parser = argparse.ArgumentParser(
        description = "Chaos engineering experiments .json to a table in latex")
    parser.add_argument("-f", "--file", required=True, help="the experiment result file (.json)")
    parser.add_argument("-s", "--steady-state", required=True, dest="steady_state", help="json file that describes the steady state")
    parser.add_argument("-l", "--logs", required=True, help="path to the logs of experiment results folder")
    parser.add_argument("-p", "--p-value", type=float, required=True, dest="p_value", help="p-value threshold")
    parser.add_argument("-t", "--template", default="ce", choices=['ce', 'benchmark'], help="the template to be used")
    parser.add_argument("-c", "--client", required=True, choices=['geth', 'openethereum'], help="the client's name")
    parser.add_argument("--csv", action='store_true', help="generate a csv file of the results")
    parser.add_argument("--plot", help="plot the samples CDFs", action='store_true')
    args = parser.parse_args()

    return args

def ks_compare_metrics(steady_state_metrics, experiment, logs_folder, p_value_threshold, plot):
    post_recovery_metrics = read_post_recovery_metrics(logs_folder, experiment)
    log_folder = os.path.join(logs_folder, "%s%s-%s"%(experiment["syscall_name"], experiment["error_code"], experiment["failure_rate"]))
    normal_metrics = list()
    for metric in steady_state_metrics:
        metric_name = metric["metric_name"]
        ss_metric_points = np.array(metric["data_points"]).astype(float)
        pr_metric_points = np.array(post_recovery_metrics[metric_name]["values"]).astype(float)
        t = ks_2samp(ss_metric_points[:,1], pr_metric_points[:,1])
        if t.pvalue > p_value_threshold: normal_metrics.append(metric_name)
        if plot: plot_metric(log_folder, ss_metric_points[:,1], pr_metric_points[:,1], metric_name)
    return ", ".join(normal_metrics)

def plot_metric(log_folder, data_s1, data_s2, metric):
    fig = plt.figure()
    ax = fig.add_subplot()
    #-----------------------------
    # Sample 1 CDF plot 
    #-----------------------------
    data_s1_df = pd.DataFrame(data_s1, columns=[metric])
    stats_df = data_s1_df.groupby(metric)[metric].agg('count').pipe(pd.DataFrame).rename(columns={metric: 'frequency'})

    # PDF
    stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])

    # CDF
    stats_df['cdf'] = stats_df['pdf'].cumsum()
    stats_df = stats_df.reset_index()

    stats_df.plot(x=metric, y=['pdf','cdf'], grid=True, ax=ax, label=['Sample 1 PDF', 'Sample 1 CDF'])

    #-----------------------------
    # Sample 2 CDF plot 
    #-----------------------------
    data_s2_df = pd.DataFrame(data_s2, columns=[metric])
    stats_df = data_s2_df.groupby(metric)[metric].agg('count').pipe(pd.DataFrame).rename(columns = {metric: 'frequency'})

    # PDF
    stats_df['pdf'] = stats_df['frequency'] / sum(stats_df['frequency'])

    # CDF
    stats_df['cdf'] = stats_df['pdf'].cumsum()
    stats_df = stats_df.reset_index()

    stats_df.plot(x=metric, y=['pdf','cdf'], grid=True, ax=ax, label=['Sample 2 PDF', 'Sample 2 CDF'])

    fig.savefig(log_folder + "/" + metric + ".pdf")
    plt.close(fig)

def read_post_recovery_metrics(logs_folder, experiment):
    log_file_name = "post_recovery_phase_metrics.json"
    log_file_path = os.path.join(logs_folder, "%s%s-%s"%(experiment["syscall_name"], experiment["error_code"], experiment["failure_rate"]), log_file_name)
    with open(log_file_path, 'rt') as file:
        metrics = json.load(file)
        return metrics

def round_number(x, sig=3):
    return round(x, sig - int(math.floor(math.log10(abs(x)))) - 1)

def generate_csv(experiments):
    with open("experiment_results.csv", "w", newline = "") as csvfile:
        metric_names = list(experiments[0]["result"]["metrics"]["normal"].keys())
        header = ["error_model", "injection_count", "client_crashed"] + metric_names
        csv_writer = csv.DictWriter(csvfile, fieldnames = header)
        csv_writer.writeheader()
        for experiment in experiments:
            row = dict()

            error_model = "%s,%s,%s"%(experiment["syscall_name"], experiment["error_code"][1:], experiment["failure_rate"])
            row.update({"error_model": error_model})
            row.update({"injection_count": experiment["result"]["injection_count"]})
            row.update({"client_crashed": experiment["result"]["client_crashed"]})
            metric_values = dict()
            for metric in metric_names:
                if experiment["result"]["client_crashed"]:
                    metric_values[metric] = "%.2f"%(experiment["result"]["metrics"]["normal"][metric]["mean"])
                else:
                    metric_values[metric] = "%.2f/%.2f/%.2f"%(experiment["result"]["metrics"]["normal"][metric]["mean"], experiment["result"]["metrics"]["ce"][metric]["mean"], experiment["result"]["metrics"]["post_recovery"][metric]["mean"])
            row.update(metric_values)

            csv_writer.writerow(row)

def main(args):
    with open(args.file, 'rt') as file, open(args.steady_state, 'rt') as steady_state_file:
        data = json.load(file)
        ss_data = json.load(steady_state_file)
        ss_metrics = ss_data["other_metrics"]

        if args.csv: generate_csv(data["experiments"])

        body = ""
        for experiment in data["experiments"]:
            if experiment["result"]["injection_count"] == 0: continue

            body += "%s& %s& %s& %d& %s& %s\\\\\n"%(
                experiment["syscall_name"],
                experiment["error_code"][1:], # remove the "-" before the error code
                round_number(experiment["failure_rate"]),
                experiment["result"]["injection_count"],
                "X" if experiment["result"]["client_crashed"] else "",
                "" if experiment["result"]["client_crashed"] else ks_compare_metrics(ss_metrics, experiment, args.logs, args.p_value, args.plot)
            )
        body = body[:-1] # remove the very last line break
        latex = TEMPLATE_CE_RESULTS%(args.client, args.client, body)
        latex = latex.replace("_", "\\_")
        print(latex)

if __name__ == "__main__":
    logger_format = '%(asctime)-15s %(levelname)-8s %(message)s'
    logging.basicConfig(level=logging.INFO, format=logger_format)

    args = get_args()
    main(args)