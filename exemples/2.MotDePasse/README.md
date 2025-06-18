# Exercice 1 - **Mot de passe**

## Sujet

Ce programme en C demande à l'utilisateur de saisir un mot de passe. Si le mot de passe est correct, il affiche un **flag secret**. Sinon, il affiche un message de refus d’accès.

Mais l’utilisateur n’a aucun indice sur le mot de passe attendu…  
Le but est donc d’utiliser le **débuggeur** pour trouver le mot de passe et déclencher l’affichage du **flag caché**.

## Objectifs pédagogiques

- valider les acquis après **l'introduction**.
- Poser des **points d’arrêt** (breakpoints).
- Suivre l’exécution ligne par ligne.

## Résolution 
<details>
  <summary>Solution</summary>


  ### Étape 1 : Identifier la logique contrôle

  Dans la vue Disassembly, on observe :


    0x7ff6ef3b1636 call 0x7ff6ef3bf6b0 ; <strcmp>
    0x7ff6ef3b163b test eax, eax
    0x7ff6ef3b163d jne 0x7ff6ef3b1664 ; saut si strcmp échoue
    0x7ff6ef3b163f call 0x7ff6ef3b1506 ; <secret>


  Si strcmp échoue (eax != 0), l'exécution saute la fonction secret.

  ### Étape 2 – Explorer la fonction secret
  Même si secret() n’est pas exécutée, on peut la sélectionner dans la liste des fonctions à gauche (secret) puis observer son contenu désassemblé:


    0x7ff6ef3b1506 lea rax, [rip+0x40f9] ; adresse du message
    0x7ff6ef3b150d mov rdi, rax
    0x7ff6ef3b1510 call 0x7ff6ef3b1048 ; <printf>


  On voit que secret() affiche un message stocké en mémoire à l’adresse RIP + 0x40f9.

  ### Étape 3 – Calculer l’adresse réelle du message

  L’adresse effective est :
  0x7ff6ef3b1506 (RIP actuel) + 0x40f9

  ### Étape 4 – Lire le flag dans la mémoire


    0x00007ff6efb40ff9 | 00 00 00 00 00 00 00 46 4c 41 47 20 3a 20 45 44  | .......FLAG : ED
    0x00007ff6efb41009 | 55 44 42 47 5f 4d 45 49 4c 4c 45 55 52 5f 44 45  | UDBG_MEILLEUR_DE
    0x00007ff6efb41019 | 42 55 47 47 45 52 20 0a 00 45 6e 74 65 72 20 70  | BUGGER



</details>