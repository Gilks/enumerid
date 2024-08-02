#!/usr/bin/env bash
echo "manually installing pipenv enviroment"
if ! command -v pipenv & > /dev/null
then
  echo "pipenv is not installed"
  echo "install using: python3 -m pipenv"
fi

if command -v pipenv & > /dev/null
then
  export PIPENV_VENV_IN_PROJECT=True && pipenv --site-packages install
fi