#!/usr/bin/env python3
"""Turn results/*.json into figures (PDF/PNG) and LaTeX table snippets.

Usage: python3 scripts/make_figures.py [results_dir] [out_dir]
Only the Python standard library is needed for the tables; matplotlib is
needed for the figures (skipped with a warning if unavailable).
"""
import json
import math
import os
import statistics
import sys

RES = sys.argv[1] if len(sys.argv) > 1 else "results"
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join("report", "generated")
os.makedirs(OUT, exist_ok=True)

SETS = [s for s in ["S", "M", "L"] if os.path.exists(os.path.join(RES, f"bench_{s}.json"))]
DATA = {s: json.load(open(os.path.join(RES, f"bench_{s}.json"))) for s in SETS}
LABEL = {"S": r"S ($n{=}2^{16}$, $N{=}8192$)", "M": r"M ($n{=}2^{20}$, $N{=}8192$)", "L": r"L ($n{=}2^{20}$, $N{=}16384$)"}
SHORT = {"S": "S: n=2^16, N=8192", "M": "M: n=2^20, N=8192", "L": "L: n=2^20, N=16384"}


def runs(s, threads):
    return [r for r in DATA[s]["runs"] if int(r["threads"]) == threads]


def med(s, threads, key):
    v = [r[key] for r in runs(s, threads) if key in r]
    return statistics.median(v) if v else float("nan")


def iqr(s, threads, key):
    v = sorted(r[key] for r in runs(s, threads) if key in r)
    if len(v) < 4:
        return (min(v), max(v))
    q = statistics.quantiles(v, n=4)
    return (q[0], q[2])


def mb(x):
    return x / 1e6


def fmt_ms(x):
    return f"{x:,.0f}" if x >= 100 else (f"{x:.1f}" if x >= 1 else f"{x:.2f}")


def fmt_bytes(x):
    if x >= 1e6:
        return f"{x/1e6:.2f} MB"
    if x >= 1e3:
        return f"{x/1e3:.1f} KB"
    return f"{x:.0f} B"


def write(name, text):
    with open(os.path.join(OUT, name), "w") as f:
        f.write(text)


tables = {}

# --------------------------------------------------------------------------
# Parameter table
# --------------------------------------------------------------------------
rows = []
for s in SETS:
    p = DATA[s]["params"]
    rows.append(
        f"{s} & $2^{{{int(math.log2(p['n']))}}}$ & {p['N']} & {p['log2q']} ({p['log2q_data']}) & {p['t']:,} & "
        f"{p['B']} & {p['alpha']} & {p['capacity']} & {p['flood_bits']} & $2^{{{p['log2_overflow']:.0f}}}$ & $2^{{{p['log2_fp']:.0f}}}$ \\\\"
    )
write("tab_params.tex", "\n".join(rows) + "\n")

# --------------------------------------------------------------------------
# Online time breakdown (medians)
# --------------------------------------------------------------------------
STAGES = [
    ("Client: OPRF blind", "cli.oprf_blind_ms"),
    ("Server: OPRF eval + DLEQ proof", None),
    ("Client: verify proof + finalize", None),
    ("Client: cuckoo + keygen + encrypt", None),
    ("Server: load + validate", "srv.load_ms"),
    ("Server: powers (49 ct$\\times$ct)", None),
    ("Server: partition evaluation", "srv.partitions_ms"),
    ("Server: rerandomize + flood + mod-switch", "srv.flood_modswitch_ms"),
    ("Client: unpack + decrypt + decode", None),
]


def stage_val(s, th, i):
    g = lambda k: med(s, th, k)
    return [
        g("cli.oprf_blind_ms"),
        g("srv.oprf_eval_ms") + g("srv.oprf_proof_ms"),
        g("cli.oprf_verify_ms") + g("cli.oprf_finalize_ms"),
        g("cli.cuckoo_ms") + g("cli.keygen_ms") + g("cli.encrypt_ms"),
        g("srv.load_ms"),
        g("srv.powers_ms") + g("srv.powers_ntt_ms"),
        g("srv.partitions_ms"),
        g("srv.flood_modswitch_ms") + g("srv.pack_ms"),
        g("cli.unpack_ms") + g("cli.decode_ms"),
    ][i]


lines = []
for i, (name, _) in enumerate(STAGES):
    cells = []
    for s in SETS:
        for th in (1, 2):
            cells.append(fmt_ms(stage_val(s, th, i)))
    lines.append(f"{name} & " + " & ".join(cells) + " \\\\")
tot = []
srv = []
cli = []
for s in SETS:
    for th in (1, 2):
        tot.append(r"\textbf{" + fmt_ms(med(s, th, "srv.total_ms") + med(s, th, "cli.total_ms")) + "}")
        srv.append(fmt_ms(med(s, th, "srv.total_ms")))
        cli.append(fmt_ms(med(s, th, "cli.total_ms")))
lines.append(r"\midrule")
lines.append("Server total & " + " & ".join(srv) + " \\\\")
lines.append("Client total & " + " & ".join(cli) + " \\\\")
lines.append(r"\textbf{Compute total} & " + " & ".join(tot) + " \\\\")
iq = []
for s in SETS:
    for th in (1, 2):
        lo, hi = iqr(s, th, "srv.total_ms")
        iq.append(f"{fmt_ms(lo)}--{fmt_ms(hi)}")
lines.append(r"\quad server IQR & " + " & ".join(iq) + " \\\\")
write("tab_time.tex", "\n".join(lines) + "\n")

# --------------------------------------------------------------------------
# Communication / object sizes (identical across runs: fixed shape)
# --------------------------------------------------------------------------
def one(s, k):
    return DATA[s]["runs"][0][k]


SIZE_ROWS = [
    ("OPRF request ($256\\times32$ B)", "size.oprf_up", "up"),
    ("OPRF response + DLEQ proof (64 B)", "size.oprf_down", "down"),
    ("Public key $pk_C$ (seeded)", "size.pk", "up"),
    ("Relinearization keys $rlk_C$ (seeded)", "size.rlk", "up"),
    ("Query: 14 ciphertexts (seeded)", "size.query_cts", "up"),
    ("Response: $2\\alpha$ ciphertexts (bit-packed)", "size.response", "down"),
]
lines = []
for name, k, d in SIZE_ROWS:
    lines.append(f"{name} & {d} & " + " & ".join(fmt_bytes(one(s, k)) for s in SETS) + " \\\\")
lines.append(r"\midrule")
lines.append("One query ciphertext & up & " + " & ".join(fmt_bytes(one(s, "size.query_ct_each")) for s in SETS) + " \\\\")
lines.append("One response ciphertext & down & " + " & ".join(fmt_bytes(one(s, "size.response_ct_each")) for s in SETS) + " \\\\")
lines.append(r"\midrule")
lines.append(r"\textbf{Total upload} & & " + " & ".join(r"\textbf{" + fmt_bytes(one(s, "size.total_up")) + "}" for s in SETS) + " \\\\")
lines.append(r"\textbf{Total download} & & " + " & ".join(r"\textbf{" + fmt_bytes(one(s, "size.total_down")) + "}" for s in SETS) + " \\\\")
write("tab_size.tex", "\n".join(lines) + "\n")

# --------------------------------------------------------------------------
# Preprocessing + memory
# --------------------------------------------------------------------------
lines = []
for s in SETS:
    pr = DATA[s]["preprocess"]
    me = DATA[s]["memory"]
    lines.append(
        f"{s} & {pr['pre.oprf_ms']/1000:.1f} & {pr['pre.binning_ms']/1000:.1f} & {pr['pre.poly_ms']/1000:.1f} & "
        f"{pr['pre.encode_ms']/1000:.1f} & \\textbf{{{(pr['pre.oprf_ms']+pr['pre.binning_ms']+pr['pre.poly_ms']+pr['pre.encode_ms'])/1000:.1f}}} & "
        f"{int(pr['pre.max_bin_load'])}/{int(pr['pre.capacity'])} & {int(pr['pre.collisions_skipped'])} & "
        f"{me['mem.p_coeffs_MB']+me['mem.l_plain_MB']:.0f} \\\\"
    )
write("tab_pre.tex", "\n".join(lines) + "\n")

# --------------------------------------------------------------------------
# Noise budgets
# --------------------------------------------------------------------------
lines = []
NOISE = [("Fresh query ciphertext", "noise.fresh"), ("After powers (depth 1)", "noise.powers"),
         ("After partition evaluation", "noise.evaluated"), ("After rerandomize + flood", "noise.flooded"),
         ("After mod-switch to $q_0$ (sent)", "noise.final")]
for name, k in NOISE:
    lines.append(f"{name} & " + " & ".join(f"{DATA[s]['noise'][k]:.0f}" for s in SETS) + " \\\\")
lam = []
for s in SETS:
    p = DATA[s]["params"]
    log2E = p["log2q_data"] - math.log2(p["t"]) - DATA[s]["noise"]["noise.evaluated"] - 1
    lam.append(p["flood_bits"] - log2E - math.log2(p["N"]))
lines.append(r"\midrule")
lines.append("Flooding width $b$ (bits) & " + " & ".join(str(DATA[s]["params"]["flood_bits"]) for s in SETS) + " \\\\")
lines.append(r"Statistical parameter $\lambda=b-\log_2 E_{\mathrm{eval}}-\log_2 N$ & " + " & ".join(f"{x:.0f}" for x in lam) + " \\\\")
write("tab_noise.tex", "\n".join(lines) + "\n")

# --------------------------------------------------------------------------
# Baselines
# --------------------------------------------------------------------------
lines = []
for s in SETS:
    b = DATA[s]["baselines"]
    psi_t = med(s, 2, "srv.total_ms") + med(s, 2, "cli.total_ms")
    psi_up, psi_down = one(s, "size.total_up"), one(s, "size.total_down")
    lines.append(f"\\multirow{{3}}{{*}}{{{s}}} & Plaintext lookup & {b['base.plain_server_ms']*1000:.0f}\\,\\textmu s & "
                 f"{fmt_bytes(b['base.plain_up_bytes'])} / {fmt_bytes(b['base.plain_down_bytes'])} & 256 (full hash) \\\\")
    lines.append(f" & $k$-anon.\\ prefix ({int(b['base.kanon_prefix_bits'])} bits) & "
                 f"{(b['base.kanon_server_ms']+b['base.kanon_client_ms'])*1000:.0f}\\,\\textmu s & "
                 f"{fmt_bytes(b['base.kanon_up_bytes'])} / {fmt_bytes(b['base.kanon_down_bytes'])} & {int(b['base.kanon_prefix_bits'])} \\\\")
    lines.append(f" & This work (HE-uPSI) & {psi_t/1000:.2f}\\,s & {fmt_bytes(psi_up)} / {fmt_bytes(psi_down)} & 0 \\\\")
    if s != SETS[-1]:
        lines.append(r"\midrule")
write("tab_baseline.tex", "\n".join(lines) + "\n")

# --------------------------------------------------------------------------
# Scaling in n on the N=8192 ring: S (2^16), M (2^20), optional M_n22 (2^22)
# --------------------------------------------------------------------------
SCALE = [("S", DATA.get("S")), ("M", DATA.get("M"))]
p22 = os.path.join(RES, "bench_M_n22.json")
if os.path.exists(p22):
    SCALE.append(("M_n22", json.load(open(p22))))
SCALE = [(k, d) for k, d in SCALE if d]


def med_d(d, threads, key):
    v = [r[key] for r in d["runs"] if int(r["threads"]) == threads and key in r]
    return statistics.median(v) if v else float("nan")


lines = []
for k, d in SCALE:
    p = d["params"]
    pr = d["preprocess"]
    me = d["memory"]
    r0 = d["runs"][0]
    lines.append(
        f"$2^{{{int(math.log2(p['n']))}}}$ & {p['alpha']} & {pr['pre.total_ms']/1000:.0f} & "
        f"{me['mem.p_coeffs_MB']+me['mem.l_plain_MB']:.0f} & {med_d(d, 1, 'srv.total_ms')/1000:.2f} & "
        f"{med_d(d, 2, 'srv.total_ms')/1000:.2f} & {int(r0['size.response_cts'])} & {fmt_bytes(r0['size.total_up'] + r0['size.total_down'])} \\\\"
    )
write("tab_scale.tex", "\n".join(lines) + "\n")
if len(SCALE) >= 2:
    a, b = SCALE[-2][1], SCALE[-1][1]
    per_alpha_1 = med_d(b, 1, "srv.total_ms") / b["params"]["alpha"]
    print("server ms per partition (1 thread):", round(per_alpha_1, 1))

# --------------------------------------------------------------------------
# Numbers used in the prose (\newcommand macros)
# --------------------------------------------------------------------------
macros = {}
for s in SETS:
    for th in (1, 2):
        macros[f"Tot{s}{'One' if th == 1 else 'Two'}"] = f"{(med(s, th, 'srv.total_ms') + med(s, th, 'cli.total_ms'))/1000:.2f}"
        macros[f"Srv{s}{'One' if th == 1 else 'Two'}"] = f"{med(s, th, 'srv.total_ms')/1000:.2f}"
    macros[f"Cli{s}"] = f"{med(s, 1, 'cli.total_ms'):.0f}"
    macros[f"Up{s}"] = f"{mb(one(s, 'size.total_up')):.2f}"
    macros[f"Down{s}"] = f"{mb(one(s, 'size.total_down')):.2f}"
    macros[f"Comm{s}"] = f"{mb(one(s, 'size.total_up') + one(s, 'size.total_down')):.1f}"
    macros[f"Pre{s}"] = f"{(DATA[s]['preprocess']['pre.total_ms'])/1000:.1f}"
    macros[f"Final{s}"] = f"{DATA[s]['noise']['noise.final']:.0f}"
    b = DATA[s]["baselines"]
    psi_t = med(s, 2, "srv.total_ms") + med(s, 2, "cli.total_ms")
    macros[f"SlowPlain{s}"] = f"{psi_t / (b['base.plain_server_ms']):,.0f}"
    macros[f"BytesPlain{s}"] = f"{(one(s, 'size.total_up') + one(s, 'size.total_down')) / (b['base.plain_up_bytes'] + b['base.plain_down_bytes']):,.0f}"
    macros[f"BytesKanon{s}"] = f"{(one(s, 'size.total_up') + one(s, 'size.total_down')) / (b['base.kanon_up_bytes'] + b['base.kanon_down_bytes']):.0f}"
    macros[f"KanonDown{s}"] = fmt_bytes(b["base.kanon_down_bytes"])
    tps = sum(r["ok.tp"] for r in DATA[s]["runs"])
    macros[f"Runs{s}"] = str(len(DATA[s]["runs"]))
    macros[f"TP{s}"] = str(int(tps))
    macros[f"FP{s}"] = str(int(sum(r["ok.fp"] for r in DATA[s]["runs"])))
    macros[f"FN{s}"] = str(int(sum(r["ok.fn"] for r in DATA[s]["runs"])))
    macros[f"Lerr{s}"] = str(int(sum(r["ok.label_err"] for r in DATA[s]["runs"])))
first = DATA[SETS[0]]
macros["CPU"] = first["cpu"].replace("(R)", "").replace("(TM)", "").strip()
macros["HWThreads"] = str(first["hw_threads"])
write("numbers.tex", "".join(f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in macros.items()))

# --------------------------------------------------------------------------
# Figures
# --------------------------------------------------------------------------
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except Exception as e:  # pragma: no cover
    print("matplotlib unavailable, skipping figures:", e)
    sys.exit(0)

plt.rcParams.update({"font.size": 9, "axes.spines.top": False, "axes.spines.right": False,
                     "font.family": "serif", "pdf.fonttype": 42})
PAL = ["#2a6f97", "#61a5c2", "#a9d6e5", "#e07a5f", "#f2cc8f", "#81b29a", "#3d405b", "#b5838d", "#6d597a"]

# Fig 1: stacked time breakdown
fig, ax = plt.subplots(figsize=(6.6, 2.15))
labels, bottoms = [], []
xs = []
for s in SETS:
    for th in (1, 2):
        labels.append(f"{s}\n{th} thr")
idx = list(range(len(labels)))
bottom = [0.0] * len(labels)
for i, (name, _) in enumerate(STAGES):
    vals = []
    for s in SETS:
        for th in (1, 2):
            vals.append(stage_val(s, th, i) / 1000)
    ax.bar(idx, vals, bottom=bottom, color=PAL[i % len(PAL)], width=0.62, label=name.replace("$\\times$", "×"),
           edgecolor="white", linewidth=0.4)
    bottom = [b + v for b, v in zip(bottom, vals)]
for x, b in zip(idx, bottom):
    ax.text(x, b + 0.05, f"{b:.2f}s", ha="center", va="bottom", fontsize=7.5)
ax.set_xticks(idx)
ax.set_xticklabels(labels)
ax.set_ylabel("online compute time (s)")
ax.set_ylim(0, max(bottom) * 1.18)
ax.legend(fontsize=6.6, ncol=1, frameon=False, loc="upper left", bbox_to_anchor=(1.0, 1.02))
fig.tight_layout()
fig.savefig(os.path.join(OUT, "fig_time.pdf"))
fig.savefig(os.path.join(OUT, "fig_time.png"), dpi=170)
plt.close(fig)

# Fig 2: communication breakdown
fig, ax = plt.subplots(figsize=(6.6, 1.65))
parts = [("OPRF", ["size.oprf_up", "size.oprf_down"]), ("pk$_C$", ["size.pk"]), ("rlk$_C$", ["size.rlk"]),
         ("query cts", ["size.query_cts"]), ("response cts", ["size.response"])]
y = list(range(len(SETS)))[::-1]
left = [0.0] * len(SETS)
for i, (name, keys) in enumerate(parts):
    vals = [mb(sum(one(s, k) for k in keys)) for s in SETS]
    ax.barh(y, vals, left=left, color=PAL[[6, 1, 2, 0, 3][i]], height=0.55, label=name, edgecolor="white", linewidth=0.4)
    left = [a + b for a, b in zip(left, vals)]
for yy, l in zip(y, left):
    ax.text(l + 0.2, yy, f"{l:.1f} MB", va="center", fontsize=7.5)
ax.set_yticks(y)
ax.set_yticklabels([SHORT[s] for s in SETS])
ax.set_xlabel("bytes on the wire per query (MB)")
ax.set_xlim(0, max(left) * 1.15)
ax.legend(fontsize=7, ncol=5, frameon=False, loc="lower center", bbox_to_anchor=(0.45, 1.0))
fig.tight_layout()
fig.savefig(os.path.join(OUT, "fig_comm.pdf"))
fig.savefig(os.path.join(OUT, "fig_comm.png"), dpi=170)
plt.close(fig)

# Fig 3: flooding sweep
sweeps = [(n, os.path.join(RES, f"flood_{n}.json")) for n in ("M", "L")]
sweeps = [(n, json.load(open(p))) for n, p in sweeps if os.path.exists(p)]
if sweeps:
    fig, ax = plt.subplots(figsize=(6.6, 1.95))
    for (n, d), c in zip(sweeps, [PAL[0], PAL[3]]):
        bits = sorted({pt["flood_bits"] for pt in d["points"]})
        fin = [min(pt["final"] for pt in d["points"] if pt["flood_bits"] == b) for b in bits]
        ok = [all(pt["correct"] for pt in d["points"] if pt["flood_bits"] == b) for b in bits]
        ax.plot(bits, fin, "-o", color=c, ms=3.5, lw=1.4, label=f"N={d['N']}, log q$_{{data}}$={d['log2q_data']}")
        for b, f, o in zip(bits, fin, ok):
            if not o:
                ax.plot([b], [f], "x", color="black", ms=6)
        ev = statistics.median(pt["evaluated"] for pt in d["points"])
        log2E = d["log2q_data"] - math.log2(d["t"]) - ev - 1
        b40 = log2E + math.log2(d["N"]) + 40
        ax.axvline(b40, color=c, ls=":", lw=1)
        ax.text(b40 + 0.6, 2 if n == "M" else 9, f"λ=40\n(b≈{b40:.0f})", color=c, fontsize=7)
        chosen = DATA.get(n, {}).get("params", {}).get("flood_bits")
        if chosen:
            fc = min(pt["final"] for pt in d["points"] if pt["flood_bits"] == chosen) if chosen in bits else None
            if fc is not None:
                ax.plot([chosen], [fc], "s", color=c, ms=7, mfc="none", mew=1.4)
    ax.axhline(0, color="#888", lw=0.8)
    ax.set_xlabel("flooding width b (bits): noise uniform in [−2$^b$, 2$^b$)")
    ax.set_ylabel("noise budget left\nin response (bits)")
    ax.legend(fontsize=7, frameon=False, loc="lower left")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig_flood.pdf"))
    fig.savefig(os.path.join(OUT, "fig_flood.png"), dpi=170)
    plt.close(fig)

print("wrote tables and figures to", OUT)
