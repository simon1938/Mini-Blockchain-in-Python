
import random
import string
from ecdsa import SigningKey, NIST384p
import hashlib

#Génération des clé

private_key = SigningKey.generate(curve=NIST384p)
public_key = private_key.get_verifying_key()

class Block:
    
    def __init__(self, previous_block_hash, transaction_list, private_key=None):

        self.previous_block_hash = previous_block_hash
        self.transaction_list = transaction_list

        # on considère qu'il y a qu'une transaction par block et donc qu'une private key
        if(private_key == None):
            self.signature = None
        else:
            self.signature = private_key.sign(self.transaction_list[0].encode()).hex()

        #compteur de tentative
        self.count_try = -1
        # nombre de zéros souhaité pour la preuve de travail 
        target_zeros = 3  

        while True:
            self.count_try += 1
            #chaine de caractère aléatoire qui change à chaque itération
            proof_of_work = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            self.block_data = f"{' - '.join(transaction_list)} - {previous_block_hash} - {proof_of_work}"
            self.block_hash = hashlib.sha256(self.block_data.encode()).hexdigest()

            # Vérifie si le hash du bloc commence par le nombre de zéros requis
            if self.block_hash.startswith('0' * target_zeros):
                print("Le nombre de tentatives fut de " + str(self.count_try) + " fois")
                break
  
        
    # Vérifie la signature du bloc en utilisant la clé publique fournie
    # Si la signature est absente, considère le bloc comme valide
    # Sinon, vérifie la signature en décodant la signature hexadécimale et en vérifiant avec la clé publique
    # Retourne True si la signature est valide, False sinon
    def check_signature(self, public_key):
        if(self.signature == None):
            return True
        else:
            try:               
                public_key.verify(bytes.fromhex(self.signature), self.transaction_list[0].encode())
                return True
            except:               
                return False
        
class Blockchain:
    def __init__(self):
        self.chain = []
        self.generate_genesis_block()

    def generate_genesis_block(self):
        self.chain.append(Block("0", ['Genesis Block']))
    
    def create_block_from_transaction(self, transaction_list):
        previous_block_hash = self.last_block.block_hash
        self.chain.append(Block(previous_block_hash, transaction_list))

    #Fonction d'ajout de block avec signature
    def create_block_from_transaction_and_private_key(self, transaction_list, private_key):
        previous_block_hash = self.last_block.block_hash
        self.chain.append(Block(previous_block_hash, transaction_list, private_key))


    def display_chain(self):
        for i in range(len(self.chain)):
            print(f"Data {i + 1}: {self.chain[i].block_data}")
            print(f"Hash {i + 1}: {self.chain[i].block_hash}\n")

    # Vérifie la validité de la blockchain en vérifiant la signature de chaque bloc
    # en utilisant la clé publique fournie
    # Parcourt tous les blocs de la chaîne et vérifie la signature de chaque bloc
    def verif_blockchain(self,public_key):
        for i in range(len(self.chain)):            
            #On vérifie la signature de chaque block
            if(self.chain[i].check_signature(public_key) == False):
                return False
        return True

    @property
    def last_block(self):
        return self.chain[-1]


t1 = "L'employeur me verse 2000 €"
t2 = "J'ai dépensé 70 € chez Total"
t3 = "J'ai dépensé 5 € chez amazone"
t4 = "J'ai dépensé 100 € chez Auchan"
t5 = "J'ai dépensé 110 € chez Engi"
t6 = "J'ai dépensé 30 € chez SFR"

myblockchain = Blockchain()
myblockchain.create_block_from_transaction([t1])
myblockchain.create_block_from_transaction_and_private_key([t2], private_key)
myblockchain.create_block_from_transaction_and_private_key([t3], private_key)
myblockchain.create_block_from_transaction_and_private_key([t4], private_key)
myblockchain.create_block_from_transaction_and_private_key([t5], private_key)
myblockchain.create_block_from_transaction_and_private_key([t6], private_key)
myblockchain.display_chain()

#test pour question 4
# block_to_modify = myblockchain.chain[1]
# block_to_modify.signature = "incorrect_signature"

# Verification de la blockchain
if myblockchain.verif_blockchain(public_key):
    print("Valide")
else:
    print("Pas valide")