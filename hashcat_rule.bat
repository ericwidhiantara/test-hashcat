@echo off
hashcat.exe -a 0 -m 11300 hashes.txt nicklist.txt -r nick_1989.rule --session=bf --status --status-timer=10 -o FOUND.txt
pause