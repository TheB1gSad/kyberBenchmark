from cProfile import label
from kyber import Kyber512
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os
from time import time



class main:
    def printData (timeToKeyGen, timeToDecrypt, timeToEncrypt, timeToRunTotal, trials):
        print("Average Time For Key Generation")
        print(timeToKeyGen/trials)
        print("Average Time For Encryption")
        print(timeToEncrypt/trials)
        print("Average Time For Decryption")
        print(timeToDecrypt/trials)
        print("Average Total Runtime")
        print(timeToRunTotal/trials)


    userIn = input("Input How Many Trials You Want To Run" + '\n')
    trials = int(userIn) 
    

    
    #Start of Kyber Benchmark
    print('\n'+"Beginning Benchmark For Kyber 512")
    print('-'*33)
    timeToEncrypt=0
    timeToDecrypt = 0
    timeToKeyGen = 0
    timeToRunTotal = 0
    for i in range(trials):
        totalTime = time()
        timeInitial = time()
        pk, sk = Kyber512.keygen()
        timeToKeyGen+=time()-timeInitial

        timeInitial = time()
        ct,k = Kyber512.enc(pk)
        timeToEncrypt+=time()-timeInitial

        timeInitial = time()
        Kyber512.dec(ct,sk)
        timeToDecrypt+=time()-timeInitial

        timeToRunTotal+=time()-totalTime

    printData(timeToKeyGen,timeToEncrypt,timeToDecrypt,timeToRunTotal,trials)
    print('-'*33,'\n')
    #End of Kyber Benchmark


    #Beginning Of AES128 Benchmark
    timeToEncrypt=0
    timeToDecrypt = 0
    timeToKeyGen = 0
    timeToRunTotal = 0
    print("Beginning AES 128 Benchmark")
    print('-'*33)

    for i in range(trials):
        totalTime = time()
        timeInitial = time()
        key = os.urandom(16)
        timeToKeyGen+=time()-timeInitial

        timeInitial = time()
        obj = AES.new(key, AES.MODE_EAX)
        message = os.urandom(32)
        ciphertext = obj.encrypt(message)
        timeToEncrypt+=time()-timeInitial

        timeInitial = time()
        obj2 = AES.new(key, AES.MODE_EAX,obj.nonce)
        aesDecryption =  obj2.decrypt(ciphertext)
        timeToDecrypt+=time()-timeInitial

        timeToRunTotal+=time()-totalTime

    printData(timeToKeyGen,timeToEncrypt,timeToDecrypt,timeToRunTotal,trials)
    print('-'*33,'\n')

    #Beginning Of AES256 Benchmark
    timeToEncrypt=0
    timeToDecrypt = 0
    timeToKeyGen = 0
    timeToRunTotal = 0
    print("Beginning AES 256 Benchmark")
    print('-'*33)

    for i in range(trials):
        totalTime = time()
        timeInitial = time()
        key = os.urandom(32)
        timeToKeyGen+=time()-timeInitial

        timeInitial = time()
        obj = AES.new(key, AES.MODE_EAX)
        message = os.urandom(32)
        ciphertext = obj.encrypt(message)
        timeToEncrypt+=time()-timeInitial

        timeInitial = time()
        obj2 = AES.new(key, AES.MODE_EAX,obj.nonce)
        aesDecryption =  obj2.decrypt(ciphertext)
        timeToDecrypt+=time()-timeInitial

        timeToRunTotal+=time()-totalTime
    printData(timeToKeyGen,timeToEncrypt,timeToDecrypt,timeToRunTotal,trials)
    print('-'*33,'\n')

    #End of AES256 Benchmark
  
    #Beginning Of RSA 2048 Benchmark
    timeToEncrypt=0
    timeToDecrypt = 0
    timeToKeyGen = 0
    timeToRunTotal = 0
    print("Beginning RSA 2048 Benchmark")
    print('-'*33)

    for i in range(trials):
        if i%10==0:
            print(i)
        totalTime = time()
        timeInitial = time()
        key = RSA.generate(2048)
        timeToKeyGen+=time()-timeInitial

        timeInitial = time()
        cipher = PKCS1_OAEP.new(key)
        message = os.urandom(32)
        ciphertext = cipher.encrypt(message)
        timeToEncrypt+=time()-timeInitial

        timeInitial = time()
      
        cipher.decrypt(ciphertext)
        timeToDecrypt+=time()-timeInitial

        timeToRunTotal+=time()-totalTime
    printData(timeToKeyGen,timeToEncrypt,timeToDecrypt,timeToRunTotal,trials)
    print('-'*33)
    
  

    



    





