import serial
import time

def sent(name, str):
    sents = serial.Serial(name, 9600, timeout = 5)
    print("串口=%s, 波特率=9600"%(sents.name))
    strings = "[SENT {}]{}".format((time.asctime(time.localtime(time.time()))), str)
    print(strings)
    sents.write(strings.encode())
    sents.close()

sent("COM1", "How are you?")
