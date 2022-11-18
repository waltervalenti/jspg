#!/usr/bin/python3

import json
from dataclasses import dataclass
from dataclasses_json import dataclass_json
import gpg, sys
import base64
from gpg.constants.sig import mode


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
            print("comandi: sign|enc|sign-enc|verify|dec")
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
            if len(sys.argv) != 3:
                print("Uso: verify [file]")
                sys.exit(-1)
            input_file = sys.argv[2]
            self.verify(input_file)
        if cmd == "dec":
            state = True
            if len(sys.argv) != 3:
                print("Uso: dec [file]")
                sys.exit(-1)
            input_file = sys.argv[2]
            self.decrypt(input_file)
        if state == False:
            print("comando %s sconosciuto", cmd)

    def sign(self, id_keys, input_file):
        with open(input_file, "rb") as f:
            signature = self.__impl_sign(id_keys, input_file)
            data = Signatures(base64.b64encode(f.read()).decode("utf-8"), base64.b64encode(signature).decode("utf-8"))
            print(data.to_json())
            
    def encrypt(self, id_keys, input_file):
        cypher = self.__impl_enc(id_keys, input_file)
        data = Encrypt(base64.b64encode(cypher).decode("utf-8"))
        print(data.to_json())
                
    def sign_enc(self, id_keys_sign, id_keys_enc, input_file):
        signature  = self.__impl_sign(id_keys_sign, input_file)
        cypher = self.__impl_enc(id_keys_enc, input_file)
        data = SignEnc(base64.b64encode(cypher).decode("utf-8"), base64.b64encode(signature).decode("utf-8"))
        print(data.to_json())
        
    def verify(self, input_file):
        c = gpg.Context()
        f = json.load(open(input_file))
        enc = False
        try:
            plain = f['plain']
        except:
            encrypted = f['encrypted']
            enc = True
        signatures = f['signatures']
        if enc == True:
            plain, _, _ = c.decrypt(base64.b64decode(encrypted))
        data, result = c.verify(plain, base64.b64decode(signatures))
        for sign in result.signatures:
            print(sign.fpr, c.get_key(sign.fpr).uids[0].uid)
            
    def decrypt(self, input_file):
        c = gpg.Context()
        f = json.load(open(input_file))
        encrypted = f['encrypted']
        plainfile, _, _ = c.decrypt(base64.b64decode(encrypted))
        sys.stdout.buffer.write(plainfile)
                
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
        
######################################################################################################################

jspg = Jspg()

