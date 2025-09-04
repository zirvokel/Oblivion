# Oblivion

> **Oblivion** est une solution de transfert contrôlé et automatisé de fichiers entre deux domaines Active Directory totalement isolés, via une passerelle Linux sécurisée.

---

## 🚀 Présentation

Dans certains environnements sensibles (banques, administrations, infrastructures critiques), il existe plusieurs domaines **Active Directory** totalement isolés les uns des autres. 

La question devient alors : *comment permettre à un utilisateur autorisé de transférer un fichier de manière sécurisée entre ces mondes cloisonnés ?*

**Oblivion** répond à ce besoin.  

Il s’agit d’un **relais Linux** assurant des transferts automatiques de fichiers entre deux domaines distincts, sans jamais ouvrir de communication directe entre eux.  

Les échanges reposent sur une logique de **répertoires IN/OUT** synchronisés par un service robuste.

---

## 📐 Architecture

- **DOM1** : `192.168.10.0/24`
  
  - Contrôleur de domaine : `192.168.10.2`
  - Comptes suffixés en `.dmz`

- **DOM2** : `10.10.240.0/24`
  
  - Contrôleur de domaine : `10.10.240.2`
  - Comptes suffixés en `.adm`

- **Passerelle Oblivion (Linux)** :
  
  - Interface DOM1 : `192.168.10.1`
  - Interface DOM2 : `10.10.240.1`
  - Service de synchronisation `systemd` toutes les **10 secondes**

Chaque utilisateur autorisé dispose de deux répertoires transactionnels :  

```
Transactions/
└── user.suffix/
├── IN   # Fichiers à envoyer vers l’autre domaine
└── OUT  # Fichiers reçus depuis l’autre domaine
````

---

## 🔧 Fonctionnement

1. **Création des comptes** :
   
   - Utilisateurs créés automatiquement via script PowerShell (`dc1.ps1` / `dc2.ps1`).  
   - Ajoutés au groupe de sécurité `DMZ_2_ADM`.  
   - Répertoires `IN` et `OUT` créés avec ACLs spécifiques.

3. **Relais Linux** :
   
   - Monte les partages `Transactions` de DOM1 et DOM2 en **CIFS**.  
   - Exécute `/usr/local/sbin/ftbridge_sync.sh` en service `systemd`.  
   - Synchronisation **bidirectionnelle** toutes les 10 secondes.  
   - Logs détaillés dans `/var/log/ftbridge/sync.log`.

5. **Transfert** :
   
   - Fichiers stables déposés dans `IN` → transférés automatiquement vers `OUT` de l’autre domaine.  
   - Contrôles d’intégrité basés sur la taille des fichiers.  

---

## ⚙️ Installation

### 1. Sur chaque contrôleur de domaine (DC1 & DC2)

Exécuter le script PowerShell correspondant :  

```powershell
.\dc1.ps1   # Sur DOM1
.\dc2.ps1   # Sur DOM2
````

Ces scripts :

* Créent le groupe `DMZ_2_ADM`
* Configurent le partage `Transactions`
* Appliquent les ACLs correctes
* Préparent les comptes de service (`svc_relay_dom1`, `svc_relay_dom2`)

---

### 2. Sur la passerelle Linux

Télécharger et exécuter le script d’installation :

```bash
curl -o /opt/setup_relay.sh https://github.com/<ORG>/oblivion/setup_relay.sh
chmod +x /opt/setup_relay.sh
sudo /opt/setup_relay.sh
```

Ce script :

* Configure les interfaces réseaux
* Installe les dépendances (`rsync`, `cifs-utils`, `smbclient`)
* Monte les partages `Transactions`
* Installe `ftbridge_sync.sh`
* Crée un **service systemd + timer (10s)**

---

## 📊 Journalisation

Tous les transferts sont tracés :

```
[2025-09-04 11:02:13] === CYCLE ===
[2025-09-04 11:02:13] DOM1->DOM2 : j.doe.dmz/IN -> j.doe.adm/OUT
[2025-09-04 11:02:13] DOM2->DOM1 : f.golgo.adm/IN -> f.golgo.dmz/OUT
```

Les logs sont stockés dans :

```
/var/log/ftbridge/sync.log
```

---

## 🔒 Sécurité

* **Aucun routage** entre DOM1 et DOM2 (`net.ipv4.ip_forward=0`)
* **Isolation stricte** via répertoires personnels
* **ACLs Windows** garantissant que seul l’utilisateur + service dédié peuvent accéder aux fichiers
* **Relais unidirectionnel contrôlé** → aucun accès direct entre domaines

---

## 🛠️ Améliorations prévues

* [x] Synchronisation bidirectionnelle corrigée et fiable
* [x] Gestion des utilisateurs et correction des erreurs de permissions
* [ ] Intégration de **ClamAV** pour l’analyse antivirale des fichiers transférés
* [ ] Renforcement de la sécurité Linux (**hardening**, pare-feu, services minimaux)
* [ ] Amélioration de la verbosité et de la traçabilité des logs Linux
* [ ] Mise en place d’une **file d’attente** (queue) pour gérer les copies de fichiers
* [ ] Génération automatique d’un **rapport ClamAV** dans le répertoire OUT de l’utilisateur
* [ ] Ajout de paramètres pour basculer entre **mode unidirectionnel** et **bidirectionnel**
* [ ] Documentation détaillée pour un **déploiement en production** sécurisé
* [ ] (Roadmap) Développement d’une **interface graphique (GUI)** pour simplifier l’administration

---

## 📝 Licence

Distribué sous licence **Apache 2.0**.
Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## 🤝 Contribution

Les contributions sont bienvenues !

Merci de :

1. Forker le repo
2. Créer une branche (`feature/ma-fonction`)
3. Soumettre une PR détaillée

---

## 👨‍💻 Auteurs

* **Fede**
