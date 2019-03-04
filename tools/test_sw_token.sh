#!/bin/bash

./main

while [ $? == 100 ] ; do
    echo "Restarting software authentictor."
    ./main
done
