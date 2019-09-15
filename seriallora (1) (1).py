#!/usr/bin/python3
import serial 
import subprocess
import re
import csv
import datetime

class Lora:
    def __init__(self, s):
        self.buf = bytearray()
        self.s = s
    
    def readline(self):
        i = self.buf.find(b"\n")        
        if i >= 0:
            r = self.buf[:i+1]
            self.buf = self.buf[i+1:]
            return r
        while True:
            i = max(1, min(2048, self.s.in_waiting))
            data = self.s.read(i)
            i = data.find(b"\n")
            if i >= 0:
                r = self.buf + data[:i+1]
                self.buf[0:] = data[i+1:]
                return r
            else:
                self.buf.extend(data)
                
    def log(self,fields):
        with open(r'log.csv','a',encoding='utf-8') as f:
            writer=csv.writer(f)
            writer.writerow(fields)
            
    def createDict(self,r):
        d={}
        #creating dictionary which has "=" between key and value in string
        for i in r:
            at=i.split(' = ')
            if  at[0] == 'Type' or at[0] not in d.keys():
                if at[1] == "Confirmed" or at[1].lower() == "true":
                    d[at[0]]="1"
                elif at[1] == "Unconfirmed" or at[1].lower() == "false":
                    d[at[0]]="0"
                else:
                    d[at[0]]=at[1]
        return d
    
def main():
    ser = serial.Serial('COM5', 115200)
    rl = Lora(ser)
    
    nwkey=input("Enter Network Key\n")
    appkey=input("Enter Application key\n")
    nwkey=nwkey.replace(" ","")
    appkey=appkey.replace(" ","")
    print("\nFreq,Rssi,Ack,Snr,Plaintext,Message type\n")
    
    while True:
        data=rl.readline().decode().split(",")
        out = subprocess.Popen("lora-packet-decode --nwkkey "+nwkey+" --appkey "+appkey+" --hex "+data[4][:-2], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = out.communicate()
        string = stdout.decode('utf8').replace("'", '"')
    
        r=re.findall("\w+ = \w+",string)
        
        d=rl.createDict(r)
            
        if 'Plaintext' in d.keys() and d['Type'] != "0":
            plaintext = bytearray.fromhex(d['Plaintext'].strip()).decode(errors='ignore')
            print(data[0],data[1],d['ACK'],data[3],plaintext,d['Type'])
            rl.log([datetime.datetime.now(),data[0],data[1],d['Type'],d['DevAddr'],d['FCtrl'],"0x"+d['FCnt'],d['ACK'],d['ADR'],plaintext,d['PHYPayload']])
        
        elif 'Plaintext' in d.keys():
            plaintext = bytearray.fromhex(d['Plaintext'].strip()).decode(errors='ignore')
            rl.log([datetime.datetime.now(),data[0],data[1],d['Type'],d['DevAddr'],d['FCtrl'],"0x"+d['FCnt'],d['ACK'],d['ADR'],plaintext+"Key Unknown",d['PHYPayload']])
            print(data[0],data[1],d['ACK'],data[3],plaintext+"Key Unknown",d['Type'])
        
        else:
            rl.log([datetime.datetime.now(),data[0],data[1],"It","was","Ack","or","a","bad","data",d['PHYPayload']])
            
if __name__=="__main__":
    main()