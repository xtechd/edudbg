# Cours 5 - Reverse simple (sans code source)

## Objectifs

* Apprendre à analyser un programme **sans code source**
* Utiliser EduDbg pour deviner la logique du programme
* Explorer le comportement d'une fonction

## Prérequis

* Avoir suivi les cours 1 à 4
* Avoir le fichier exécutable `guess_me.exe` fourni

Code source utilisé pour la compilation (non fourni aux élèves) :

```c
#include <stdio.h>

int check(int input) {
    if (input == 1337) {
        return 1;
    }
    return 0;
}

int main() {
    int val = 0;
    check(val);
    return 0;
}
```

## Contexte du reverse

* Ici, l’objectif est de découvrir ce que fait `check()`
* Tu n'as pas le code source ! Tu dois analyser le comportement via le débogueur

## Pratique avec EduDbg

### 1. Ouvrir `guess_me.exe`

* Breakpoint automatique sur `main`

### 2. Explorer les fonctions disponibles

* Liste à gauche : double-cliquer sur `check`
* Lire le disassembly de cette fonction

### 3. Repérer une comparaison

* Regarder les instructions `cmp`, `je`, `jne`
* Quelle valeur est comparée ? Contre quoi ?

### 4. Poser des breakpoints stratégiques

* Avant `cmp` pour voir les registres (quelle est la valeur de `val` ?)
* Modifier le registre directement (avancé)

## Objectif pratique

1. Trouver la condition de succès dans `check`
2. Identifier la valeur attendue (via `cmp`)
3. Déduire l’input correct à donner

## Challenge !

Crée une version modifiée de `guess_me.exe` (si tu as le code source) qui contient deux conditions :

```c
if (input == 1337 && input2 == 42)
```

Observe les deux comparaisons successives dans le disassembly.

## Astuce debug

* Tu peux copier l'adresse de `check` et poser un breakpoint dessus
* Pour forcer une valeur dans un registre, une modification de `RAX` est possible mais avancée

---