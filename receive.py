import serial
import time

def rece(str):
    reces = serial.Serial(str, 9600, timeout = 5)
    print("串口=%s, 波特率=9600"%(reces.name))
    print("RECU from COM4: "+reces.readline().decode())
    reces.close()

rece("COM4")
