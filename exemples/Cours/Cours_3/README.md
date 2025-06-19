# Cours 3 - Appels de fonctions & pile

## Objectifs

* Comprendre la structure d'appel de fonctions en bas niveau
* Visualiser le fonctionnement de la pile (stack)
* Suivre un enchaînement de fonctions avec EduDbg

## Prérequis

* Avoir suivi les cours 1 et 2
* Avoir le fichier exécutable `call_chain.exe` fourni

Code source utilisé pour la compilation (pour référence) :

```c
#include <stdio.h>

void fonction_b() {
    printf("Inside fonction_b\n");
}

void fonction_a() {
    printf("Inside fonction_a\n");
    fonction_b();
}

int main() {
    fonction_a();
    return 0;
}
```

## Théorie rapide : la pile et les appels

Quand une fonction est appelée :

1. L'adresse de retour est empilée sur la pile
2. Le `RSP` (stack pointer) est décrémenté
3. Des variables locales peuvent être empilées
4. Le `ret` revient à l'adresse appelante

## Pratique avec EduDbg

### 1. Ouvrir `call_chain.exe`

* Break automatique sur `main`
* Utiliser **Step** pour descendre dans les appels

### 2. Explorer la pile

* Onglet **Stack** : observer les adresses empilées
* Chaque appel à une fonction ajoute une adresse de retour

### 3. Observer les instructions

* Repérer `call fonction_a`, puis `call fonction_b`
* Suivre les retours `ret`

## Objectif pratique

1. Suivre les adresses dans **Stack** avant et après chaque appel
2. Repérer l'effet de `call` (le `RSP` diminue)
3. Observer l'effet de `ret` (le `RSP` remonte et le `RIP` change)

## Challenge !

Ajoute une nouvelle fonction `fonction_c()` qui appelle `fonction_a()` deux fois.
Observe l'effet dans la pile : combien d'adresses de retour apparaissent ?

## Astuce

* Tu peux faire un **double-clic** sur `fonction_a` ou `fonction_b` dans EduDbg pour voir leur désassemblage
* Cela t’aidera à visualiser leur contenu exact

---

Prochain cours → *Breakpoints et exploration mémoire (HexView)*