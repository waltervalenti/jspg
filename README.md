# jspg

jspg in a simple wrapper of gpg in JSON format.

Why use jspg ? .. Why not ? !!!

## Usage:
comandi: sign|enc|sign-enc|verify|dec|help
default: file jspg

sign: firma un file. crea file.jspg

enc:  cifra un file. crea file.jspg

sign-enc: firma e cifra un file. crea crea file.jspg

verify: verifica le firme in file.jspg - se cifrato richide la password

dec: decifra file.jspg e crea file

file.jspg: azione di default. prova decifrare e vefificare le firme se presenti

in tutti i casi, se un file esiste già, viene creato un nuovo file con .NUM nel nome

## Author
waltervalenti at yahoo.it
