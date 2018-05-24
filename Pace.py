from smartcard.util import toHexString

# needs pycryptodome (pip install pycryptodomex)
from Crypto.Random import get_random_bytes

from binascii import hexlify
from ecdsa.ellipticcurve import Point, CurveFp
from ecdsa.curves import Curve

#pip install pytlv
from pytlv.TLV import *

import binascii
import logging
import utils
from PyPaceCrypto import PyPaceCrypto


class Pace:
    
    def __init__(self, connection):
        logging.getLogger()
        self.__load_brainpool()
        self.connection = connection
        self.crypto = PyPaceCrypto()

    
    def __transceiveAPDU(self, command):
        logging.debug("CAPDU: " + toHexString(command))
        data, sw1, sw2 = self.connection.transmit( command )
        logging.debug("RAPDU Data: " + toHexString(data))
        logging.debug("RAPDU SW: %02x %02x" % (sw1, sw2))
        return bytearray(data)
    
    
    def __getX1(self):
        self.__PCD_SK_x1 = utils.hex_to_int(bytearray(get_random_bytes(32)))
        PCD_PK_X1 = self.pointG * self.__PCD_SK_x1
        return bytearray(bytearray([0x04])+utils.long_to_bytearray(PCD_PK_X1.x())+ utils.long_to_bytearray(PCD_PK_X1.y()))
    
    
    def __getX2(self, PICC_PK, decryptedNonce):
        x = PICC_PK[1:33]
        y = PICC_PK[33:]
        
        pointY1 = Point( self.curve_brainpoolp256r1, utils.hex_to_int(x), utils.hex_to_int(y), self._q)
        sharedSecret_P = pointY1 * self.__PCD_SK_x1
        pointG_strich = (self.pointG * utils.hex_to_int(decryptedNonce)) + sharedSecret_P
        
        self.__PCD_SK_x2 = utils.hex_to_int(bytearray(get_random_bytes(32)))
        PCD_PK_X2 = pointG_strich * self.__PCD_SK_x2
        return bytearray(bytearray([0x04])+utils.long_to_bytearray(PCD_PK_X2.x())+ utils.long_to_bytearray(PCD_PK_X2.y()))
    
    
    def __sendMSESetAt(self, pace_oid, pw_ref, chat = None):
        if (chat is None):
            apdu_mse = [0x00, 0x22, 0xc1, 0xa4, len(pace_oid)+5, 0x80, len(pace_oid)] + pace_oid + [0x83, 0x01, pw_ref]
        else:
            apdu_mse = [0x00, 0x22, 0xc1, 0xa4, len(pace_oid)+8+len(chat), 0x80, len(pace_oid)] + pace_oid + [0x83, 0x01, pw_ref] + [0x7F, 0x4C, len(chat)] + chat
        self.__transceiveAPDU(apdu_mse)
    
    
    def __sendGA1(self):
        apdu_ga1 = [0x10, 0x86, 0x00, 0x00, 0x02, 0x7c, 0x00, 0x00]
        return self.__transceiveAPDU(apdu_ga1)[4:20]
    
    
    def __sendGA2(self, PCD_PK):
        header = bytearray([0x10, 0x86, 0, 0, len(PCD_PK)+4, 0x7c, len(PCD_PK)+2, 0x81, len(PCD_PK)])
        response = self.__transceiveAPDU(list(header + PCD_PK)+[0])
        return response[4:]
    
    
    def __sendGA3(self, PCD_PK):
        header = bytearray([0x10, 0x86, 0, 0, len(PCD_PK)+4, 0x7c, len(PCD_PK)+2, 0x83, len(PCD_PK)])
        response = self.__transceiveAPDU(list(header + PCD_PK)+[0])
        return bytearray(response[4:])
    
    
    def __sendGA4(self, authToken):
        header = bytearray([0x00, 0x86, 0, 0, len(authToken)+4, 0x7c, len(authToken)+2, 0x85, len(authToken)])
        response = self.__transceiveAPDU(list(header + authToken)+[0])
        
        tlv = TLV(['86', '87', '88']) # DO87 and DO88 are optional
        
        collection = tlv.parse(binascii.hexlify(response[2:])) 
        
        if (collection.get('86') != None):
            DO86 = bytearray.fromhex(collection.get('86'))
        else:
            DO86 = None
        
        if (collection.get('87') != None):
            DO87 = bytearray.fromhex(collection.get('87'))
        else:
            DO87 = None
       
        if (collection.get('88') != None):
            DO88 = bytearray.fromhex(collection.get('88'))
        else:
            DO88 = None

        return DO86, DO87, DO88

    
    def __getSharedSecret(self, PICC_PK):
        x = PICC_PK[1:33]
        y = PICC_PK[33:]
        pointY2 = Point( self.curve_brainpoolp256r1, utils.hex_to_int(x), utils.hex_to_int(y), self._q)
        K = pointY2 * self.__PCD_SK_x2
        return utils.long_to_bytearray(K.x())
    
    
    def __calcAuthToken(self, kmac, algorithm_oid, Y2):
        oid_input = [0x06, len(algorithm_oid)] +algorithm_oid
        mac_input = [0x7f, 0x49, len(oid_input)+len(Y2)+2] + oid_input + [0x86, len(Y2)] + list(Y2)
        logging.debug("Mac input: " + toHexString(mac_input))
        return bytearray(self.crypto.getCMAC(kmac, bytearray(mac_input)))[:8]
    
    
    def __load_brainpool(self):
        # Brainpool P-256-r1
        _a = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
        _b = 0x26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
        _p = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
        _Gx = 0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
        _Gy = 0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997
        self._q = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
        
        self.curve_brainpoolp256r1 = CurveFp( _p, _a, _b)
        self.pointG = Point(self.curve_brainpoolp256r1, _Gx, _Gy, self._q)
    
    def performPACE(self, algorithm_oid, password, pw_ref, chat = None):
        self.__sendMSESetAt(algorithm_oid, pw_ref, chat)
        
        encryptedNonce = self.__sendGA1()
        logging.info("PACE encrypted nonce: " + toHexString(list(encryptedNonce)))
        #decryptedNonce = self.__decryptNonce(encryptedNonce, password)
        decryptedNonce = self.crypto.decryptBlock(self.crypto.kdf(password, 3), encryptedNonce)
        logging.info("PACE decrypted nonce: " + toHexString(list(decryptedNonce)))
    
        PCD_PK_X1 = self.__getX1()
        logging.info("PACE PCD_PK_X1: "+toHexString(list(PCD_PK_X1)))
        PICC_PK_Y1 = self.__sendGA2(PCD_PK_X1)
        logging.info("PACE PICC_PK_Y1: "+toHexString(list(PICC_PK_Y1)))
        
        PCD_PK_X2 = self.__getX2(PICC_PK_Y1, decryptedNonce)
        logging.info("PACE PCD_PK_X2: "+toHexString(list(PCD_PK_X2)))
        PICC_PK_Y2 = self.__sendGA3(PCD_PK_X2)
        logging.info("PACE PICC_PK_Y2: "+toHexString(list(PICC_PK_Y2)))
        
        sharedSecretK = self.__getSharedSecret(PICC_PK_Y2)
        logging.info("PACE Shared Secret K: "+toHexString(list(sharedSecretK)))
        
        kenc = self.crypto.kdf(sharedSecretK, 1)
        logging.info("PACE K_enc: "+toHexString(list(kenc)))
        
        kmac = self.crypto.kdf(sharedSecretK, 2)
        logging.info("PACE K_mac: "+toHexString(list(kmac)))
        
        tpcd = self.__calcAuthToken(kmac, algorithm_oid, PICC_PK_Y2)
        logging.info("PACE tpcd: "+toHexString(list(tpcd)))
    
        tpicc, car1, car2 = self.__sendGA4(tpcd)
        logging.info("PACE tpicc: "+toHexString(list(tpicc)))
        if (car1 != None):
            logging.info("CAR1: "+ car1)
        if (car2 != None):
            logging.info("CAR2: "+ car2)
        
        tpicc_strich = self.__calcAuthToken(kmac, algorithm_oid, PCD_PK_X2);
        
        if tpicc == tpicc_strich:
            logging.info("PACE established!")
            return 0
        else:
             logging.info("PACE failed!");
             return -1
