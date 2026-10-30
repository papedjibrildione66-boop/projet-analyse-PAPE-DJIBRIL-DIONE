# Rapport — Analyse des journaux du pare-feu

**Nom / Prénom : NOM Prénom** (à remplacer)

## Résumé
Le pare-feu a enregistré une semaine de trafic (du 5 au 11 octobre 2026). Après nettoyage (doublons supprimés, protocoles mis en majuscules, valeurs manquantes remplacées par la médiane), il reste **5 440 connexions**. Le trafic est dominé par HTTPS (port 443, 1 874 connexions), puis HTTP (80), DNS (53) et MQTT (1883) pour les objets connectés. **13,57 %** des connexions sont bloquées (DENY). Deux comportements anormaux se détachent nettement du trafic normal : un scan de ports et une exfiltration de données par une caméra IoT.

## Comportement suspect 1 : scan de ports depuis 192.168.1.99
- Ce PC a contacté **328 ports distincts** sur une seule cible (10.0.0.5), alors que les autres machines en contactent au plus 8 (`figures/top_ip_scan.png`).
- Il a fait **400 connexions en 15 minutes** (le 8 octobre entre 00:00 et 00:15), dont **383 bloquées** : c'est lui qui génère presque tous les DENY (383 sur 738).
- 17 connexions ont tout de même été autorisées : le scan a donc obtenu des informations sur des ports ouverts.

## Comportement suspect 2 : exfiltration depuis la caméra 192.168.1.11
- Cette caméra IoT a envoyé **environ 260 Mo** en 194 connexions, alors que les autres machines envoient environ 0,6 Mo en moyenne sur la semaine, soit **plus de 400 fois plus** (`figures/top_ip_octets.png`).
- Les envois partent surtout vers l'extérieur (8.8.8.8, 1.1.1.1) sur les ports 443, 8080 et 80, à toute heure. Une caméra ne devrait envoyer que de petits flux vers son serveur d'enregistrement : cela ressemble à une fuite de données ou à une caméra compromise.

## Recommandations de sécurité
1. **Bloquer l'IP 192.168.1.99** et analyser le PC (malware ou utilisateur malveillant). Ajouter une règle de détection de scan : alerte si une IP contacte plus de 20 ports distincts en quelques minutes.
2. **Isoler la caméra 192.168.1.11** et la réinitialiser (mot de passe, firmware). Mettre les objets IoT dans un **VLAN séparé** avec uniquement les flux nécessaires (par exemple MQTT vers le serveur interne).
3. **Fermer Telnet (port 23)** : 100 tentatives dont 26 autorisées, depuis 29 machines. Remplacer par SSH avec authentification par clé.
4. **Limiter les flux sortants** : autoriser les objets IoT uniquement vers des destinations connues, et mettre une alerte sur les volumes anormaux.
