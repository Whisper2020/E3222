import time
import serial
import threading

def sent(str):
    sents = serial.Serial(str, 9600, timeout = 5)
    print("串口=%s, 波特率=9600"%(sents.name))
    strings = "[SENT {}]{}".format((time.asctime(time.localtime(time.time()))), str)
    print(strings)
    sents.write(strings.encode())
    sents.close()
def rece(str):
    reces = serial.Serial(str, 9600, timeout = 5)
    print("串口=%s, 波特率=9600"%(reces.name))
    print("RECU from COM4: "+reces.readline().decode())
    reces.close()

if __name__ == '__main__':
    t1 = threading.Thread(target=rece, args=("COM2",))
    t2 = threading.Thread(target=sent, args=("COM1",))
    t1.start()
    t2.start()
