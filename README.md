# BTC Toy

Ce repo correspond au code à compléter pour le TP sur Bitcoin donné à l'école 2600.

## Setup

- Forker et cloner le repo
- Vous aurez besoin de python 3.11+. Il est déconseillé d'essayer d'upgrader son python système. Utiliser pyenv ou une machine virtuelle.
  - Linux: https://realpython.com/intro-to-pyenv/
  - Windows: https://pyenv-win.github.io/pyenv-win/
- Installer poetry 1.6+ https://python-poetry.org/docs/#installation
- Lancer `poetry install` dans votre repo cloné
- Lancer `source .bashrc` pour activer l'environnement virtuel
- Tenter d'executer les tests `pytest` qui devraient échouer à ce stade

## Workflow

- L'objectif du TP sera d'implémenter les exercices afin de faire passer les tests au fur à mesure.
- Toutes les commandes sont à lancer depuis la racine du repertoire
- Pour lancer des tests spécifiques:
  - `pytest tests/CHEMIN_VERS_FICHIER`
  - `pytest -k NOM_DU_TEST_OU_PARTIE_DU_NOM_DU_TEST`
- Pour afficher les prints lors de l'execution des tests ajouter l'option `-s`
- Pour afficher le nom des tests qui échouent ajouter l'option `-v`
