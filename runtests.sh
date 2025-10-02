#!/bin/bash

cd `dirname $0`

box install

exitcode=0

box stop name="cfsignaturestests"
box start directory="./tests/" serverConfigFile="./tests/server-cfsignaturestests.json"
box testbox run verbose=true || exitcode=1
box stop name="cfsignaturestests"

exit $exitcode

