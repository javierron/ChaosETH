import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.stats import ks_2samp

def get_args():
    parser = argparse.ArgumentParser( description="Summarize syscall counts and latencies.")
    parser.add_argument("-s", "--steady-state", type=str, dest="steady_state", help="steady-state csv file path")
    parser.add_argument("-c", "--under-chaos", type=str, dest="under_chaos", help="under-chaos csv file path")
    parser.add_argument("-p", "--p-value", type=float, dest="p_value", help="p-value for comparison")
    args = parser.parse_args()
    return args

def compute(args):
    data_ss = pd.read_csv('./parsed.csv')
    data_uc = pd.read_csv('./parsed.csv')
    # data_ss = pd.read_csv(args.steady_state)
    # data_uc = pd.read_csv(args.under_chaos)

    # # print(data)
    metrics = ['dir_read_c', 'dir_reads', 'tcp_conn', 'tcp_sends', 'dir_writes', 'dir_write_c', 'tcp_recvs'] 

    for metric in metrics:
        # print(metric)

        ss_metric= data_ss[metric]
        uc_metric = data_uc[metric] - 1000

        print(np.cumsum(ss_metric))

        fig = plt.figure()
        ax = plt.axes()


        ax.plot(np.cumsum(ss_metric))

        t = ks_2samp(uc_metric, ss_metric)

        # print(t)

        # result = "Different" if t.pvalue < args.p_value else "Similar"
        # print("metric: " + str(metric) + " p-value: " + str(t.pvalue) + " means: " + result)


if __name__ == "__main__":
    args = get_args()
    compute(args)