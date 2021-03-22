#!/bin/bash

DIR_FILES=$(ls artifacts)

for elem in $DIR_FILES
do
    dpkg -c artifacts/$elem
done
