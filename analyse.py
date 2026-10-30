"""Projet 1 - Analyse des journaux d'un pare-feu.

Lancement : python analyse.py
"""
import json
import os

import matplotlib
matplotlib.use("Agg")  # pas d'affichage : on enregistre seulement les PNG
import matplotlib.pyplot as plt
import pandas as pd

DATA = "data/logs_reseau.csv"
FIG_DIR = "figures"


def nettoyer(df):
    """Nettoyage : doublons, casse du protocole, bytes_sent manquants."""
    df = df.drop_duplicates().copy()
    df["protocol"] = df["protocol"].str.upper()
    mediane = df["bytes_sent"].median()  # calculée après suppression des doublons
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def calculer_resultats(df):
    """Calcule les 5 résultats demandés."""
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(df.groupby("src_ip")["dst_port"].nunique().idxmax()),
        "ip_exfiltration": str(df.groupby("src_ip")["bytes_sent"].sum().idxmax()),
    }


def sauver(nom):
    plt.tight_layout()
    plt.savefig(os.path.join(FIG_DIR, nom), dpi=120)
    plt.close()


def faire_figures(df, res):
    os.makedirs(FIG_DIR, exist_ok=True)

    # 1. Top 10 des ports
    df["dst_port"].value_counts().head(10).sort_values().plot.barh(color="steelblue")
    plt.title("Top 10 des ports de destination")
    plt.xlabel("Nombre de connexions")
    plt.ylabel("Port")
    sauver("top_ports.png")

    # 2. Connexions par heure
    df.groupby(df["timestamp"].dt.hour).size().plot.bar(color="seagreen")
    plt.title("Connexions par heure de la journée")
    plt.xlabel("Heure")
    plt.ylabel("Nombre de connexions")
    sauver("connexions_par_heure.png")

    # 3. Volume d'octets par type d'appareil
    (df.groupby("device_type")["bytes_sent"].sum() / 1e6).sort_values().plot.bar(color="darkorange")
    plt.title("Volume d'octets envoyés par type d'appareil")
    plt.xlabel("Type d'appareil")
    plt.ylabel("Mégaoctets envoyés")
    plt.xticks(rotation=0)
    sauver("octets_par_appareil.png")

    # 4. Répartition ALLOW / DENY
    df["action"].value_counts().plot.pie(autopct="%1.1f%%", colors=["#4c9f70", "#d9534f"])
    plt.title("Répartition ALLOW / DENY")
    plt.ylabel("")
    sauver("allow_deny.png")

    # 5. Top 10 des IP par octets envoyés (exfiltration)
    top = (df.groupby("src_ip")["bytes_sent"].sum() / 1e6).sort_values().tail(10)
    top.plot.barh(color="firebrick")
    plt.title("Top 10 des IP sources par volume envoyé")
    plt.xlabel("Mégaoctets envoyés")
    plt.ylabel("Adresse IP source")
    sauver("top_ip_octets.png")

    # 6. Ports distincts contactés par IP (scan)
    top = df.groupby("src_ip")["dst_port"].nunique().sort_values().tail(10)
    top.plot.barh(color="purple")
    plt.title("Top 10 des IP par nombre de ports distincts contactés")
    plt.xlabel("Ports distincts")
    plt.ylabel("Adresse IP source")
    sauver("top_ip_scan.png")


def main():
    df = nettoyer(pd.read_csv(DATA))
    res = calculer_resultats(df)
    faire_figures(df, res)
    with open("resultats.json", "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
