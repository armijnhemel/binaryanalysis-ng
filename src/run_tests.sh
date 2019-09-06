#!/bin/sh

d=`dirname "$0"`

python3 -m unittest discover "$d" -v -p 'Test*'

