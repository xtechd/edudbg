# Cours 2 - Registres & Disassembly

## Objectifs

* Comprendre les registres généraux du CPU (RAX, RIP, etc.)
* Apprendre à suivre l’exécution d’un programme pas à pas
* Lire et interpréter le code assembleur (disassembly)

## Prérequis

* Avoir suivi le Cours 1.
* Avoir le fichier exécutable `add_two_numbers.exe` fourni.

Code source pour référence :

```c
#include <stdio.h>

int main() {
    int a = 3;
    int b = 4;
    int sum = a + b;
    printf("Sum: %d\n", sum);
    return 0;
}
```

## Théorie rapide : les registres

Les registres sont des zones mémoire internes au CPU. Voici quelques-uns des plus importants :

* **RAX** : registre principal (souvent pour les résultats)
* **RBX, RCX, RDX** : registres généraux
* **RSP / RBP** : pile (stack pointer / base pointer)
* **RIP** : adresse de l’instruction en cours

## Pratique avec EduDbg

### 1. Ouvrir le fichier

* Lancer EduDbg et charger `add_two_numbers.exe`
* Attendre le break sur `main`

### 2. Observer les registres

* Onglet **Registers** : on y voit les valeurs actuelles
* Identifier : `RAX`, `RBX`, `RIP`, etc.

### 3. Utiliser **Step** pour suivre l'exécution

* Appuyer plusieurs fois sur **Step**
* Surveillez comment **RIP** progresse (c'est l'adresse de l'instruction active)

### 4. Lire le disassembly

* Onglet **Disassembly** : liste des instructions assembleur exécutées
* Repérer les instructions : `mov`, `add`, `call`

## 🔍 Interprétation du code

Cherchez ces éléments :

* Le moment où les constantes `3` et `4` sont chargées
* L’addition : instruction `add`
* L’appel à `printf` : instruction `call`

## Objectif pratique

1. Identifier le moment où `a` et `b` sont stockés en mémoire ou dans des registres
2. Trouver l'instruction `add` qui calcule la somme
3. Observer la valeur de `sum` à travers un registre (probablement `RAX` ou `EDX`)

## Astuce debug

* Active **HexView** autour de `RSP` pour voir les valeurs temporairement stockées
* Ajoute un breakpoint juste avant le `printf` si besoin

## Challenge !

Modifie le programme pour ajouter une soustraction ou une multiplication.
Observe les instructions correspondantes dans le disassembly : `sub`, `imul`, etc.

---

Prochain cours → *Appels de fonctions et analyse de la pile*