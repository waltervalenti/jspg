#!/usr/bin/python3

import json
from dataclasses import dataclass
from dataclasses_json import dataclass_json
import gpg, sys
import base64
from gpg.constants.sig import mode
from os.path import exists
import re

@dataclass_json
@dataclass
class Signatures:
    plain : str
    signatures : str
    
@dataclass_json
@dataclass
class Encrypt:
    encrypted : str
    
@dataclass_json
@dataclass
class SignEnc:
    encrypted : str
    signatures : str

class Jspg:
    def __init__(self):
        if len(sys.argv) == 1:
            print("comandi: sign|enc|sign-enc|verify|dec|help")
            print("default: file jspg")
            sys.exit(-1)
        cmd = sys.argv[1]
        state =False
        if cmd == "sign":
            state = True
            if len(sys.argv) != 4:
                print("Uso: sign [chiave1],<chiave2>,<chiaveN> [file]")
                sys.exit(-1)
            id_keys = sys.argv[2]
            input_file = sys.argv[3]
            self.sign(id_keys, input_file)
        if cmd == "enc":
            state = True
            if len(sys.argv) != 4:
                print("Uso: enc [chiave1],<chiave2>,<chiaveN> [file]")
                sys.exit(-1)
            id_keys = sys.argv[2]
            input_file = sys.argv[3]
            self.encrypt(id_keys, input_file)
        if cmd == "sign-enc":
            state = True
            if len(sys.argv) != 5:
                print("Uso: sign-enc [chiave_sign_1],<chiave_sign_2>,<chiave_sign_N> [chiave_enc_1],<chiave_enc_2>,<chiave_enc_N> [file]")
                sys.exit(-1)
            id_keys_sign = sys.argv[2]
            id_keys_enc = sys.argv[3]
            input_file = sys.argv[4]
            self.sign_enc(id_keys_sign, id_keys_enc, input_file)
        if cmd == "verify":
            state = True
            if len(sys.argv) != 3 or not str.endswith(sys.argv[2], ".jspg"):
                print("Uso: verify [file.jspg]")
                sys.exit(-1)
            input_file = sys.argv[2]
            self.verify(input_file)
        if cmd == "dec":
            state = True
            if len(sys.argv) != 3 or not str.endswith(sys.argv[2], ".jspg"):
                print("Uso: dec [file.jspg]")
                sys.exit(-1)
            input_file = sys.argv[2]
            self.decrypt(input_file)
        if len(sys.argv) == 2 and cmd.endswith(".jspg"):
            state = True
            input_file = cmd
            self.default(input_file)
        if cmd == "help" and len(sys.argv) == 2:
            state = True
            self.help()
        if state == False:
            print(f"comando \"{cmd}\" sconosciuto")

    def sign(self, id_keys, input_file):
        with open(input_file, "rb") as f:
            signature = self.__impl_sign(id_keys, input_file)
            data = Signatures(base64.b64encode(f.read()).decode("utf-8"), base64.b64encode(signature).decode("utf-8"))
            #print(data.to_json())
            self.__write_jspg(input_file, data.to_json())
            
    def encrypt(self, id_keys, input_file):
        cypher = self.__impl_enc(id_keys, input_file)
        data = Encrypt(base64.b64encode(cypher).decode("utf-8"))
        #print(data.to_json())
        self.__write_jspg(input_file, data.to_json())
                
    def sign_enc(self, id_keys_sign, id_keys_enc, input_file):
        signature  = self.__impl_sign(id_keys_sign, input_file)
        cypher = self.__impl_enc(id_keys_enc, input_file)
        data = SignEnc(base64.b64encode(cypher).decode("utf-8"), base64.b64encode(signature).decode("utf-8"))
        #print(data.to_json())
        self.__write_jspg(input_file, data.to_json())
        
    def verify(self, input_file):
        c = gpg.Context()
        try:
            f = json.load(open(input_file))
        except:
            print(f"file \"{input_file}\" non valido")
            sys.exit(-1)
        enc = False
        try:
            plain = base64.b64decode(f['plain'])
        except:
            try:
                encrypted = f['encrypted']
                enc = True
            except:
                print('"plain" o "encrypted" non presenti')
                sys.exit(-1)
        try:
            signatures = f['signatures']
        except:
            print('"signatures" non presente')
            sys.exit(-1)
        if enc == True:
            plain, _, _ = c.decrypt(base64.b64decode(encrypted))
        data, result = c.verify(plain, base64.b64decode(signatures))
        for sign in result.signatures:
            print(sign.fpr, c.get_key(sign.fpr).uids[0].uid)
            
    def decrypt(self, input_file):
        c = gpg.Context()
        try:
            f = json.load(open(input_file))
        except:
            print(f"file \"{input_file}\" non valido")
            sys.exit(-1)
        try:
            encrypted = f['encrypted']
        except:
            print('"encrypted" non presente')
            sys.exit(-1)
        plain, _, _ = c.decrypt(base64.b64decode(encrypted))
        #sys.stdout.buffer.write(plain)
        self.__write_plain(input_file, plain)

    def default(self, input_file):
        c = gpg.Context()
        try:
            f = json.load(open(input_file))
        except:
            print(f"file \"{input_file}\" non valido")
            sys.exit(-1)
        enc = True
        signed = False
        try:
            encrypted = f['encrypted']
        except:
            try:
                plain = base64.b64decode(f['plain'])
            except:
                print('"plain" o "encrypted" non presenti')
                sys.exit(-1)
            enc = False
        if enc == True:
            plain, _, _ = c.decrypt(base64.b64decode(encrypted))
            #sys.stdout.buffer.write(plain)
            self.__write_plain(input_file, plain)
        try:
            signatures = f['signatures']
            signed = True
        except:
            pass
        if signed == True:
            data, result = c.verify(plain, base64.b64decode(signatures))
            for sign in result.signatures:
                print(sign.fpr, c.get_key(sign.fpr).uids[0].uid)
                
    def help(self):
        print("sign:\t\tfirma un file. crea file.jspg")
        print("enc:\t\tcifra un file. crea file.jspg")
        print("sign-enc:\tfirma e cifra un file. crea file.jspg")
        print("verify:\t\tverifica le firme in file.jspg - se cifrato richide la password")
        print("dec:\t\tdecifra file.jspg e crea file")
        print("file.jspg:\tazione di default. prova decifrare e vefificare le firme se presenti")
        print()
        print("in tutti i casi, se un file esiste già, viene creato un nuovo file con .NUM nel nome")
        
        
    def __impl_sign(self, id_keys, input_file):
        keys = []
        for k in id_keys.split(","):
            key = list(gpg.Context().keylist(pattern=k))
            keys.extend(key)
        with gpg.Context(signers=keys) as c:
            with open(input_file, "rb") as f:
                signature, _ = c.sign(f, mode=gpg.constants.sig.mode.DETACH)
                return signature
            
    def __impl_enc(self, id_keys, input_file):
        with gpg.Context(armor=False) as c:
            recipients = []
            for k in id_keys.split(","):
                new = list(c.keylist(k))
                recipients.extend(new)
            with open(input_file, "rb") as f:
                cypher, _, _ = c.encrypt(f.read(), recipients, sign=False)
                return cypher
        
    def __write_jspg(self, input_file, content, Num = 0):
        if Num == 0:
            rip = ""
        else:
            rip = "." + str(Num)
        output_file = input_file + rip + ".jspg"
        if exists(output_file):
            self.__write_jspg(input_file, content, Num = Num + 1)
            return 0
        f = open(output_file, "w")
        f.write(content)
        f.close()
        
    def __write_plain(self, input_file, content, Num = 0):
        if Num == 0:
            rip = []
        else:
            rip = [str(Num)]
        input_file_splitted = str.split(input_file, ".")
        l = len(input_file_splitted)
        if l > 2:
            head = input_file_splitted[0: l - 2]
            tail = [input_file_splitted[l - 2]]
        else:
            head = [input_file_splitted[0]]
            tail = []
        output_file = str.join("." , head + rip +  tail)
        if exists(output_file):
            self.__write_plain(input_file, content, Num = Num + 1)
            return 0
        f = open(output_file, "wb")
        f.write(content)
        f.close()
 
        
######################################################################################################################

jspg = Jspg()

