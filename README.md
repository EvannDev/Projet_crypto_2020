# CRYPTO
Projet Crypto cyber 2020

Language: JAVA

# Réponses aux questions du projet
## Algorithme, taille de clef, mode d'opération, padding
### Taille de blocs

D'après le règlement général de sécurité ainsi que des consignes du projet, nous allons partir sur un algorithme de chiffrement par bloc.
Comme il est dit dans la partie A.1.1.1 du RGS, le chiffrement par bloc permet de chiffrer et de traiter des blocs uniquement de taille fixe, relativement petite.

De plus, comme il est cité dans la partie 2.1.2.1 et comme nous souhaitons utiliser notre utilitaire de chiffrement de fichiers au-delà de l'année 2020, nous avons décidé de suivre la recommandation du RGS et donc de choisir une taille de blocs de 128 bits.

### Taille de clef

Comme dit précédemment, notre utilitaire devra continuer à exister après 2020 et d'après la section 2.1.1 du RGS, nous allons suivre la recommandation de choisir une taille de clef minimum égale à 128 bits. Après selon le type de chiffrement que nous choisirons, nous augmenterons ou pas cette taille de clef.

### Mode opératoire

Comme cité dans la partie A.1.1.1, le chiffrement par bloc ne permet de d'assurer la confidentialité des messages de taille quelconque à partir d'un chiffrement par bloc. Donc le choix du mode opératoire va permettre d'assurer cette confidentialité. De plus, d'après les recommandations du RGS (RecomModeChiff-1 à 3), le mécanisme sera non-déterministe, conjointement lié  à un mécanisme d'intégrité et il faudra que celui-ci ait été prouvé comme mécanisme sécurisé. De plus, comme cité dans la RègleModeChiff-1, il ne devra exister aucune attaque inférieure à 2^(128/2) appels de la primitive.

Après comparaison, nous allons utiliser le mode opératoire CBC (Cipher Block Chaining). En effet, dans ce mode, nous appliquons sur chaque bloc un ‘OU exclusif’ avec le chiffrement du bloc précédent avant qu’il soit lui-même chiffré. De plus, afin de rendre chaque message unique, un vecteur d'initialisation (IV) est utilisé.

Le mode ECB est fortement déconseillé du fait que, si deux blocs sont identiques, ceux-ci seront chiffrés de la même manière et donc, auront des séquences identiques.

### Padding

Nous n'allons utiliser aucun bourrage mais concernant la dérivation de clef, nous allons utiliser la fonction PBKDF2 avec du HMAC SHA-512. Le PBKDF2 applique une fonction choisie par l'utilisateur (ici un HMAC) à un mot de passe ou une phrase secrète avec un sel et répète cette opération plusieurs fois afin de générer une clé, qui peut être ensuite utilisée pour chiffrer un quelconque contenu.

 Cette génération rajoute du temps de calcul qui complique le cassage du mot de passe, notamment par force brute. Le sel ajouté permet d'éviter l'utilisation de rainbow tables et donc limite les attaques sur plusieurs mots de passe en simultané.
