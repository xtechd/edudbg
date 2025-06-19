# Cours 1 - Introduction à EduDbg

## Objectifs

* Comprendre ce qu'est un fichier exécutable PE.
* Découvrir l'interface et les fonctionnalités de base d'EduDbg.
* Charger un exécutable et observer le point d'entrée `main`.

## Prérequis

* Avoir installé EduDbg.
* Avoir le fichier exécutable `hello_world.exe` fourni dans ce dossier.

Code source utilisé pour la compilation (pour référence) :

```c
#include <stdio.h>

int main() {
    printf("Hello, EduDbg!\\n");
    return 0;
}
```

## Théorie express : le format PE

Un fichier PE (Portable Executable) est le format utilisé par Windows pour les programmes (.exe). Il contient :

* Des **sections** comme `.text` (code), `.data` (variables), etc.
* Une **table des symboles** (si compilé avec `-g`) permettant de repérer des fonctions comme `main`.

## Pratique avec EduDbg

### 1. Ouvrir le fichier dans EduDbg

* Lancer EduDbg
* Menu **File > Open file...** et choisir `hello_world.exe`
* Attendre que le message `[+] Breakpoint hit at main` apparaisse dans la console

### 2. Explorer l'interface

* **Disassembly** : le code assembleur à l'adresse actuelle
* **Registers** : les registres du CPU (RAX, RIP, etc.)
* **Stack** : les valeurs de la pile
* **HexView** : la mémoire brute
* **Debug Console** : les logs

### 3. Comprendre le point d'arrêt sur `main`

* EduDbg détecte automatiquement l'adresse de `main` grâce aux symboles LIEF
* Un breakpoint matériel est posé sur cette adresse (Dr0)

### 4. Utiliser les contrôles

* **Step** : exécute une instruction
* **Continue** : continue jusqu'à un autre breakpoint
* **Stop** : arrête le processus

## Objectif pratique

1. Appuyer sur **Step** plusieurs fois.
2. Observer les instructions qui s'exécutent avant le `printf`.
3. Identifier l'instruction `call` vers `puts` ou `printf`.

## Challenge !

Ajoute une ligne dans `main.c` :

```c
puts("Fin du programme");
```

Recompile, recharge le fichier dans EduDbg et observe le nouveau **flux d'exécution**.

## Pour aller plus loin

* Est-ce que le `ret` final se voit ?
* Quelle est la valeur de `RAX` à la fin ?

---

Prochain cours → *Découverte des registres et du disassembly*
