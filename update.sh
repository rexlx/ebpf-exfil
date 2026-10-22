#!/bin/bash

sudo systemctl stop exfil-monitor.service && sudo cp ./exfil-monitor /usr/local/bin/exfil-monitor && sudo systemctl restart exfil-monitor
