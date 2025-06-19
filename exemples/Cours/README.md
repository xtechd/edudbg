# EduDbg - Debuggeur Pédagogique pour les binaires PE (Windows)

**EduDbg** est un debuggeur interactif et visuel conçu pour les étudiants, formateurs et passionnés du bas niveau. Il permet d’explorer et d’analyser l’exécution de programmes Windows au format **PE (Portable Executable)**, tout en offrant une interface claire et didactique.

 Conçu comme un support de cours pour apprendre les bases du debugging, de l’assembleur et de l’architecture logicielle.

---

## Fonctionnalités principales

### Interface graphique claire (Tkinter)

* Navigation intuitive
* Contrôles de débogage accessibles
* Affichage temps réel des registres, de la pile et de la mémoire

### Disassembly dynamique

* Désassemblage du code exécuté
* Instructions identifiées via **Capstone**
* Affichage enrichi des appels de fonction avec symboles (ex: `call <printf>`)

### Contrôle total du débogage

* **Step** : exécute une instruction
* **Continue** : poursuit jusqu'à un autre point d’arrêt
* **Stop** : arrête le processus
* **Breakpoints matériels** : jusqu'à 4 points d’arrêt sur adresse précise

### Visualisation de la mémoire

* Vue Hexa avec interprétation ASCII
* Recherche manuelle d’adresse mémoire
* Suivi en direct des modifications de zones critiques (tableaux, variables, etc.)

### Analyse des registres

* Mise à jour automatique à chaque étape
* Décodage manuel des flags CPU (CF, ZF, SF, OF, etc.)
* Lisible et comparatif dans l’interface

### Gestion automatique des symboles (LIEF)

* Détection automatique de `main` à l'ouverture
* Repérage des fonctions utilisateur listées dans l'interface
* Double clic pour ouvrir une vue dédiée d'une fonction

---

##  Lancer EduDbg

1. Assurez-vous d'avoir Python 3 et les bibliothèques suivantes :

   ```bash
   pip install lief pefile capstone
   ```
2. Lancez le programme avec :

   ```bash
   python edudbg.py
   ```

 Nécessite Windows (interface et debugging Windows PE)

---

## Cours interactifs inclus

Une série de 5 cours pour apprendre à utiliser le débogueur tout en explorant les bases du bas niveau :

| Cours | Thème                   | Exécutable fourni     |
| ----- | ----------------------- | --------------------- |
| 1     | Introduction & `main`   | hello\_world.exe      |
| 2     | Registres & disassembly | add\_two\_numbers.exe |
| 3     | Fonctions & pile        | call\_chain.exe       |
| 4     | Breakpoints & mémoire   | array\_write.exe      |
| 5     | Reverse simple          | guess\_me.exe         |

Chaque cours dispose de son propre dossier dans `cours/` avec un `README.md` explicatif.

---

## Idéal pour :

* Les formateurs en sécurité, architecture, assembleur
* Les étudiants en informatique souhaitant apprendre visuellement
* Les curieux du fonctionnement interne des programmes

---

**Démarrez avec le Cours 1 dans `cours/01_intro/README.md`** ⇩