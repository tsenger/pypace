from smartcard.System import readers
from smartcard.util import toHexString

import logging
from Pace import Pace

reader_index = 1

pw_ref   = 2 # CAN
password = "840375"
pace_oid = [0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02] # PACE_ECDH_AES128
chat = [0x06, 0x09, 0x04, 0x00, 0x7f, 0x00, 0x07, 0x03, 0x01, 0x02, 0x02, 0x53, 0x05, 0x3f, 0xff, 0xff, 0xff, 0xf7]

def init_reader(reader_index):
    r=readers()
    connection = r[reader_index].createConnection()
    connection.connect()
    logging.info("ATR: "+toHexString(connection.getATR()))
    return connection
    

def main():
    #logging.basicConfig(filename='pace.log', format='%(asctime)s %(message)s', level=logging.DEBUG)
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
    
    connection = init_reader(reader_index)
    pace_operator = Pace(connection)
    pace_operator.performPACE(pace_oid, password, pw_ref, chat)

if __name__ == "__main__":
    main()
