# Cours 4 - Breakpoints et exploration mémoire (HexView)

## Objectifs

* Apprendre à poser des breakpoints matériels manuellement
* Visualiser la mémoire avec HexView
* Comprendre comment des données sont stockées en RAM

## Prérequis

* Avoir suivi les cours précédents
* Avoir le fichier exécutable `array_write.exe` fourni

Code source utilisé pour la compilation (pour référence) :

```c
#include <stdio.h>

int main() {
    int array[5] = {0};
    for (int i = 0; i < 5; i++) {
        array[i] = i * 2;
    }
    printf("Array filled.\n");
    return 0;
}
```

## Théorie rapide : la mémoire et les breakpoints matériels

* Chaque donnée manipulée est stockée à une adresse en mémoire
* Les breakpoints matériels permettent de s'arrêter **sur une adresse** précise
* EduDbg utilise les registres `Dr0` à `Dr3` pour ça

## Pratique avec EduDbg

### 1. Ouvrir le fichier `array_write.exe`

* Breakpoint automatique sur `main`

### 2. Avancer jusqu'à la boucle

* Utiliser **Step** jusqu'à entrer dans la boucle `for`

### 3. Trouver l'adresse du tableau

* Repérer le moment où `array[i]` est accédé
* Voir dans la **Stack** ou via **Registers** une adresse utilisée pour `mov` ou `lea`

### 4. Utiliser HexView

* Copier l'adresse observée
* La coller dans le champ HexView puis cliquer sur **Search**
* Observer comment la mémoire change à chaque itération

### 5. Ajouter un breakpoint manuel

* Coller l'adresse d'écriture dans le champ **Breakpoints**
* Cliquer sur **Add** pour poser un point d'arrêt matériel
* Le programme s'arrêtera quand cette case sera écrite

## Objectif pratique

1. Observer l'évolution de la mémoire du tableau
2. Poser un breakpoint sur une case précise (ex: `array[3]`)
3. Identifier l'instruction qui modifie cette valeur

## Challenge !

Remplace la boucle par :

```c
for (int i = 0; i < 5; i++) {
    array[i] = i * i;
}
```

Observe la différence dans HexView et dans les instructions (recherche `imul`).

## Astuce debug

* Tu peux ajouter plusieurs breakpoints matériels (max 4)
* Tu peux observer les changements ligne par ligne en cliquant sur **Step**

---

Prochain cours → *Reverse simple : analyser un programme sans code source*