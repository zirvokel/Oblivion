# Oblivion

> **Oblivion** est une solution contrôlée et automatisée de transfert de fichiers entre deux domaines Active Directory complètement isolés, via une passerelle Linux sécurisée.

---

## 🚀 Vue d’ensemble

Dans des environnements sensibles (banques, administrations, infrastructures critiques), plusieurs domaines **Active Directory** peuvent exister en isolation complète les uns des autres.

La question devient : *comment un utilisateur autorisé peut-il transférer un fichier en toute sécurité entre ces mondes cloisonnés ?*

**Oblivion** répond à cette question.

Il agit comme un **relais Linux**, automatisant les transferts de fichiers entre deux domaines distincts sans jamais ouvrir de communication directe entre eux.

Les transferts reposent sur un modèle simple mais sécurisé de **répertoires IN/OUT**, synchronisés par un service en arrière-plan robuste.

---

## 📐 Architecture

* **DOM1** : `192.168.10.0/24`

  * Contrôleur de domaine : `192.168.10.2`
  * Comptes suffixés par `.dmz`

* **DOM2** : `10.10.240.0/24`

  * Contrôleur de domaine : `10.10.240.2`
  * Comptes suffixés par `.adm`

* **Passerelle Oblivion (Linux)** :

  * Interface DOM1 : `192.168.10.1`
  * Interface DOM2 : `10.10.240.1`
  * Service de synchronisation via `systemd` toutes les **10 secondes**

Chaque utilisateur autorisé reçoit deux répertoires transactionnels :

```
Transactions/
└── utilisateur.suffixe/
    ├── IN   # Fichiers à envoyer vers l’autre domaine
    └── OUT  # Fichiers reçus depuis l’autre domaine
```

---

## 🔧 Fonctionnement

1. **Création des utilisateurs**

   * Comptes provisionnés automatiquement via PowerShell (`dc1.ps1` / `dc2.ps1`)
   * Ajoutés au groupe de sécurité `DMZ_2_ADM`
   * Répertoires `IN` et `OUT` créés avec des ACL strictes

2. **Relais Linux**

   * Monte le partage `Transactions` de chaque domaine via **CIFS**
   * Exécute `/usr/local/sbin/ftbridge_sync.sh` en tant que service `systemd`
   * Effectue une **synchronisation bidirectionnelle** toutes les 10 secondes
   * Journaux détaillés disponibles dans `/var/log/ftbridge/sync.log`

3. **Transfert de fichiers**

   * Les fichiers stables placés dans `IN` → copiés automatiquement dans `OUT` de l’autre domaine
   * La stabilité est validée par un contrôle de cohérence de la taille

---

## ⚙️ Installation

### 1. Sur chaque contrôleur de domaine (DC1 & DC2)

Exécuter le script PowerShell approprié :

```powershell
.\dc1.ps1   # Sur DOM1
.\dc2.ps1   # Sur DOM2
```

Ces scripts :

* Créent le groupe `DMZ_2_ADM`
* Configurent le partage `Transactions`
* Appliquent les ACL
* Provisionnent les comptes de service (`svc_relay_dom1`, `svc_relay_dom2`)

---

### 2. Sur la passerelle Linux

Télécharger et exécuter l’installateur :

```bash
curl -o /opt/setup_relay.sh https://github.com/<ORG>/oblivion/setup_relay.sh
chmod +x /opt/setup_relay.sh
sudo /opt/setup_relay.sh
```

Le script :

* Configure les interfaces réseau
* Installe les dépendances (`rsync`, `cifs-utils`, `smbclient`)
* Monte les partages `Transactions`
* Déploie `ftbridge_sync.sh`
* Met en place un **service + timer systemd (10s)**

---

## 📊 Journalisation

Tous les transferts sont enregistrés, par exemple :

```
[2025-09-04 11:02:13] === CYCLE ===
[2025-09-04 11:02:13] DOM1->DOM2 : j.doe.dmz/IN -> j.doe.adm/OUT
[2025-09-04 11:02:13] DOM2->DOM1 : f.golgo.adm/IN -> f.golgo.dmz/OUT
```

Les journaux sont stockés dans :

```
/var/log/ftbridge/sync.log
```

---

## 🔒 Sécurité

* **Pas de routage** entre DOM1 et DOM2 (`net.ipv4.ip_forward=0`)
* **Isolation stricte** par répertoires utilisateurs
* **ACL Windows** garantissant que seuls l’utilisateur et le service de relais accèdent aux fichiers
* **Relais contrôlé** → jamais d’accès réseau direct entre domaines

---

## 🛠️ Feuille de route

* [x] Synchronisation bidirectionnelle fiable et robuste
* [x] Gestion des utilisateurs et corrections des permissions
* [x] Intégration de **ClamAV** pour l’antivirus
* [x] Journalisation plus détaillée et traçabilité
* [x] Rapport automatique **ClamAV** déposé dans le `OUT` de l’utilisateur
* [x] Système de **file d’attente** pour gérer les copies
* [ ] Renforcement Linux (**pare-feu, services minimaux**)
* [ ] Modes de synchro configurables (**unidirectionnel/bidirectionnel**)
* [ ] Documentation de déploiement prête pour la production
* [ ] (Futur) Tableau de bord **GUI web** pour une administration simplifiée

---

## 📝 Licence

Distribué sous **Apache 2.0 License**.
Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## 🤝 Contribution

Les contributions sont les bienvenues !

Veuillez :

1. Forker le dépôt
2. Créer une branche (`feature/ma-fonctionnalité`)
3. Soumettre une PR détaillée

---

## 👨‍💻 Auteurs

* **Fede**
