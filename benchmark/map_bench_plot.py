import pandas as pd
import seaborn as sns
from matplotlib import pyplot as plt


sns.set_style("whitegrid")

df = pd.read_csv("data/map_bench_result.csv")

left   = 0.10
right  = 0.99
bottom = 0.20
top    = 0.85
wspace = 0.25
hspace = 0.60

for i, t in enumerate(["hashtable"]):
    for bench in ["insert", "change", "hit", "miss", "remove"]:
        fig, ax = plt.subplots(figsize=(12, 4), ncols=2, nrows=1)
        for mode in [0, 1]:
            plotdf = df[(df.type == i + 1) & (df.bench == bench) & (df.keymode == mode) \
                    & (df.nobjs % 4000 == 0)].drop(columns=["type", "bench"], axis=1)

            plotdf["nobjs"] = plotdf["nobjs"].map(lambda x: x / 1000)

            plot = sns.pointplot(
                x="nobjs",
                y="time",
                hue="os",
                scale=0.5,
                data=plotdf,
                legend=True,
                ax=ax[mode]
            )

            ax[mode].legend(fontsize=10).set_title("")
            ax[mode].set_title("Benchmark type: %s-%s" %
                    (bench.title(), "Forward" if mode == 0 else "Random"))
            ax[mode].set_xticklabels(plot.get_xticklabels(), rotation=-40)
            ax[mode].set(xlabel="Number of Objects [K]", ylabel="Time [usecs]")

        plt.subplots_adjust(
            left   = left,
            right  = right,
            bottom = bottom,
            top    = top,
            wspace = wspace,
            hspace = hspace
        )

        plt.savefig("plots/%s_map_bench_%s.png" % (t, bench))
        # plt.show()
        plt.close(fig)
