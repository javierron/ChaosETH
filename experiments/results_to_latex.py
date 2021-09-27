#!/usr/bin/python
# -*- coding: utf-8 -*-
# Filename: results_to_latex.py

import os, argparse, json, math, csv
import logging

TEMPLATE_CE_RESULTS = r"""\begin{table}[tb]
\scriptsize
\centering
\caption{Chaos Engineering Experiment Results on %s}\label{tab:ce-experiment-results-%s}
\begin{tabularx}{\columnwidth}{lrrrXXXX}
\toprule
\textbf{System Call}& \textbf{Error Code}& \textbf{E. R.}& \textbf{Inj.}& \textbf{H\textsubscript{C}}& \textbf{H\textsubscript{L}}& \textbf{H\textsubscript{P}}& \textbf{H\textsubscript{R}} \\
\midrule
""" + "%s" + r"""
\bottomrule
\multicolumn{8}{p{8.5cm}}{
H\textsubscript{C}: Marked if the injected errors crash the client.\newline
H\textsubscript{L}: Marked if the injected errors can be found in the client's log.\newline
H\textsubscript{P}: Marked if the injected errors have side effects on the number of connected peers.\newline
H\textsubscript{R}: Marked if the client can recover to its steady state after the error injection stops.}
\end{tabularx}
\end{table}
"""

def get_args():
    parser = argparse.ArgumentParser(
        description = "Chaos engineering experiments .json to a table in latex")
    parser.add_argument("-f", "--file", required = True, help = "the experiment result file (.json)")
    parser.add_argument("-t", "--template", default = "ce", choices = ['ce', 'benchmark'], help = "the template to be used")
    parser.add_argument("-c", "--client", required = True, choices = ['geth', 'openethereum'], help = "the client's name")
    parser.add_argument("--csv", action = 'store_true', help = "generate a csv file of the results")
    args = parser.parse_args()

    return args

def round_number(x, sig = 3):
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
    with open(args.file, 'rt') as file:
        data = json.load(file)
        if args.csv: generate_csv(data["experiments"])

        body = ""
        for experiment in data["experiments"]:
            if experiment["result"]["injection_count"] == 0: continue
            body += "%s& %s& %s& %d& %s& %s& %s& %s\\\\\n"%(
                experiment["syscall_name"],
                experiment["error_code"][1:], # remove the "-" before the error code
                round_number(experiment["failure_rate"]),
                experiment["result"]["injection_count"],
                "X" if experiment["result"]["client_crashed"] else "",
                "?",
                "?",
                "?"
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