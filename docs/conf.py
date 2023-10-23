"""Sphinx configuration."""
project = "SFR Box API"
author = "epenet"
copyright = "2022, epenet"
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx_click",
]
autodoc_typehints = "description"
html_theme = "furo"
