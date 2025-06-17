# Tutoriel EduDbg : Déboguer un programme simple pas à pas

## Objectif

Ce tutoriel a pour but d’initier les débutants à l’utilisation de notre débogueur graphique **EduDbg**, développé en Python, pour analyser un programme C très simple qui effectue une addition. Il ne nécessite **aucune connaissance préalable** en assembleur, bas niveau ou debugging.

### 1. C’est quoi un débogueur ?

Un débogueur est un outil qui permet de **regarder à l’intérieur d’un programme pendant son exécution**. Il permet notamment de :
- Exécuter le programme **pas à pas**
- **Observer** les instructions exécutées
- **Lire la mémoire**, les registres, la pile
- **Mettre des pauses** à des endroits précis du code

### 2. Préparer un programme d’exemple

Voici un petit programme C :
```c
#include <stdio.h>
int main() {

int a = 2;
int b = 3;
int c = a + b;

printf("Résultat: %d\\n", c);

return 0;

}
```
Compile-le avec les symboles de debug (important pour que le débogueur fonctionne bien) :
```
x86_64-w64-mingw32-gcc -g -O0 main.c -o main.exe
```
Le fichier main.exe sera utilisé dans EduDbg.

### 3. Lancer EduDbg

Lance edudbg.py avec Python :
```
python3 edudbg.py
```
L’interface graphique s’ouvre. Elle contient plusieurs zones :

- Console : messages d’état et événements
- Breakpoints : liste des points d’arrêt définis
- Registres : état du processeur
- Pile (stack) : mémoire temporaire des fonctions
- Disassembly : instructions exécutées
- HexView : vue brute de la mémoire
- Fonctions : fonctions détectées dans l’exécutable

### 4. Ouvrir le programme à déboguer

Menu File > Open File...

Sélectionne main.exe

EduDbg démarre le programme en pause, juste avant d’exécuter la fonction main. Il place automatiquement un point d’arrêt au début de main.

Exemple dans la console :

[+] Started process main.exe with PID XXXX

[*] Waiting for breakpoint to hit main...

[+] Breakpoint hit at main: RIP=0x...

### 5. Comprendre ce que l’on voit

**Registres**

Les registres sont des zones de stockage internes au processeur. Exemples :

RAX, RBX, RCX, etc. contiennent des valeurs intermédiaires

RIP indique l’adresse de l’instruction actuelle

**Pile (stack)**

La pile est utilisée pour stocker les variables locales et les retours de fonctions.

**Désassemblage (Disassembly)**

C’est la traduction du code machine en instructions lisibles comme :

0x140001000 mov eax, 2

0x140001003 mov ebx, 3

0x140001006 add eax, ebx

### 6. Avancer pas à pas dans le programme

Clique sur Step pour exécuter une seule instruction

Observe les changements :
RIP avance
Les registres changent
La pile se met à jour
La prochaine instruction apparaît dans le désassemblage
Répète cette action jusqu’à atteindre l’appel à printf.
Tu peux aussi utiliser Continue pour exécuter tout d’un coup jusqu’au prochain point d’arrêt.

### 7. Ajouter un point d’arrêt manuel

Repère une adresse dans la vue "Disassembly" (ex : 0x140001006)
Copie cette adresse dans la zone de saisie "Breakpoint"
Clique sur le bouton Add
Un point d’arrêt est maintenant actif à cette adresse. Lorsque tu cliques sur Continue, le programme s’arrêtera ici.

### 8. Explorer la mémoire

Dans le champ sous la zone "HexView", saisis une adresse (ex : 0x7fffffffde00)
Clique sur Search
Tu verras le contenu brut de la mémoire à cet emplacement, en hexadécimal et en ASCII.

### 9. Recharger un autre programme

Tu peux relancer un autre fichier à tout moment via le menu File > Open File.... EduDbg fermera le précédent programme, réinitialisera l’interface et te permettra de recommencer depuis le début.


### 10. Résumé des fonctionnalités

| Action | Effet |
|--- |--- |
| Open File | Charger un programme à déboguer |
| Step | Exécuter une instruction |
| Continue | Laisser le programme avancer jusqu’à un point d’arrêt |
| Stop | Terminer et nettoyer la session |
| Add Breakpoint | Définir une pause à une adresse précise |
| Hex Search | Lire le contenu de la mémoire à une adresse donnée |
