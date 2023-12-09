'''
@author: wakhsavior
'''
import socket
import sys
import struct
import time
import threading
import re
import binascii


class ChangeRequest:
    def __init__(self, ip, name, macAddress):
        self.ip = ip
        self.name = name
        self.macAddress = macAddress
        self.completed = False
        
    def complete(self):
        self.completed = True
        
    def isCompleted(self):
        return self.completed

class Camera:
    def __init__(self, const1, name, zeros1, macAddress, dataport, ip, mask, defGW, attrib, auth, zeros2,  dns1, dns2, const2, dhcp, const3, sourcepacket, respacket):
        self.ip = ip
        self.mask = mask
        self.defGW = defGW
        self.dns1 = dns1
        self.dns2 = dns2
        self.name = name        
        self.auth = auth
        self.macAddress = macAddress
        self.sourcepacket = sourcepacket
        self.const1 = const1
        self.const2 = const2
        self.const3 = const3
        self.zeros1 = zeros1
        self.zeros2 = zeros2
        self.dhcp = dhcp
        self.dataport = dataport
        self.attrib = attrib
        self.respacket = respacket
        
    def changeIp(self, newIp, newName, newMask, newGW, newDNS1, newDNS2, newAuth, newConst1,newDHCP):
        
    
        
        respacket = struct.pack('12s15s5s6s2s4s4s4s32s24s4s4s4s16s4s', newConst1, newName, self.zeros1, self.macAddress,self.dataport, newIp,newMask,newGW,self.attrib,newAuth,self.zeros2,newDNS1,newDNS2,self.const2, newDHCP)   
        print(respacket.hex())

        
        self.respacket = respacket
    
    @staticmethod
    def fromData(data):
        
        
        respacket = ''.join(['0' for i in range(0, 239)])
     #   print(respacket)
        const1, name, zeros1, macAddress,dataport, ip,mask,defGW,attrib,auth,zeros2,dns1,dns2,const2, dhcp, const3 = struct.unpack('12s15s5s6s2s4s4s4s32s24s4s4s4s16s4s100s', data) 
       # print(attrib)
       #b = binascii.hexlify(data)
       # ip = b[80:88]
       # mask = b[88:96]
       # defGW = b[96:104]
       # dns1 = b[224:232]
       # dns2 = b[232:240]
       # name = (b[24:54])
       # auth = b[168:216]
       # macAddress = b[64:76]
       # print(const2.hex())
        
        print(str(macAddress) + " : " + str(name) + " : " + str(ip) + " : " + str(mask) + " : " + str(defGW)) 
#        print(str(dns1) + " : " + str(dns2) + " : " + str(attrib))
        
 #       print(struct.calcsize(data))
    #    print(ip.hex())
        
        return Camera(const1, name, zeros1, macAddress,dataport, ip, mask,defGW,attrib,auth,zeros2,dns1,dns2,const2, dhcp, const3, data, respacket)
    
    ## Передаем байты
    
    
def convert2byte(
            param
        ):    

        param = param.strip()
   #     print(param)
        
        if (re.search(r'((\d{1,3}\.){3}(\d{1,3}))', param)) != None:
        #    print('IP')
            IP = re.search(r'((\d{1,3}\.){3}(\d{1,3}))', param).group(1)
            hex_ip = ''
            lst_oct = IP.split('.')

            
            hex_ip = hex(int(lst_oct[0]))[2:].zfill(2)+hex(int(lst_oct[1]))[2:].zfill(2)+hex(int(lst_oct[2]))[2:].zfill(2)+hex(int(lst_oct[3]))[2:].zfill(2)
                
     #       print(hex_ip)
           
            byte = bytes.fromhex(hex_ip)
    #        print(str(byte))
            return byte
            
        elif (re.search(r'((([0-9a-f]{4}\.){2}[0-9a-f]{4})|(([0-9a-f]{2}:){5}([0-9a-f]{2})))', param))  != None:
       #     print('MAC')
            if (re.search(r'(([0-9a-f]{2}:){5}([0-9a-f]{2}))', param)) != None:
                mac = re.search(r'(([0-9a-f]{2}:){5}([0-9a-f]{2}))', Line).group(1)
                mac_octets = mac.split(':')
   #             print(mac_octets)
                mac = mac_octets[0] + mac_octets[1] + mac_octets[2] + mac_octets[3] + mac_octets[4] + mac_octets[5]
                byte =  bytes.fromhex(mac)
            else:
                mac = re.search(r'((([0-9a-f]{4}\.){2}[0-9a-f]{4}))', param).group(1)
                mac_octets = mac.split('.')
                mac = mac_octets[0] + mac_octets [1] + mac_octets[2]
                byte = bytes.fromhex(mac)      
            return byte      
            
        elif (re.search(r'^[0-9a-f]{1,}$', param))  != None:
            print("AAA: " + param)
            byte = bytes.fromhex(param)
            print(byte)
            return byte
            
        else:
            print("INPUT ERROR : " + param)
 
        
        
    
def readRequestsFromFile(
                
        file
        
    ):
    
    cams = []
    IP_mac = []
    
    f = open(file)
    Lines = f.readlines()
    f.close()
    
    for Line in Lines:
 
        print(Line)
        IP_mac_params = []
        
        if ( re.search(r'(\d{1,3}\.){3}(\d{1,3})', Line) and re.search(r'((([0-9a-f]{4}\.){2}[0-9a-f]{4})|(([0-9a-f]{2}:){5}([0-9a-f]{2})))', Line))  != None:
     #       print(Line)
            if re.search(r'(([0-9a-f]{2}:){5}([0-9a-f]{2}))', Line) != None:
                mac = re.search(r'(([0-9a-f]{2}:){5}([0-9a-f]{2}))', Line).group(1)
                mac_octets = mac.split(':')
   #             print(mac_octets)
                mac = mac_octets[0] + mac_octets[1] +'.'+ mac_octets[2] + mac_octets[3] + '.' + mac_octets[4] + mac_octets[5] 
            else:
                mac = re.search(r'((([0-9a-f]{4}\.){2}[0-9a-f]{4}))', Line).group(1)
                
            #### Преобразовать в одну форму MAC
            if re.search(r'CAM', Line) != None:
                name = re.search(r'(CAM.*-\d{2,3};)',Line).group(1)
                
                hex_name = name.encode('utf-8').hex()
      #          print(hex_name)  
                
                      
            IP = re.search(r'((\d{1,3}\.){3}(\d{1,3}))', Line).group(1)
            
            byte_IP = convert2byte(IP)
            byte_mac = convert2byte(mac)   
             
            len_name_hex = len(hex_name)
            print(name + " : "+ str(len_name_hex))
            
            for i in range(len_name_hex,40):
                hex_name = hex_name + '0'
            print(hex_name)
            print(len(hex_name))
            byte_name = convert2byte(hex_name)
                   
      #      print(name + " : " + mac + " - " + IP)
            cams.append(ChangeRequest(byte_IP,byte_name,byte_mac))
    return  cams 
     
        
def change_ip(
    IPsourceaddress,
    udp_ip,
    udp_port,
    cameras,
    camerasLock,
    change_cams,
    params
        ):
    
    time.sleep(5)
    
 #   print(params)
    server_address = (IPsourceaddress, udp_port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.connect(server_address)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20)
    print("UDP target IP: " + udp_ip)
    print("UDP target port:" + str(udp_port))

    
    
    while True:
        for change_cam in change_cams:
                
            if  not change_cam.macAddress in cameras:
                    print("CAMERA ", change_cam.name.decode('utf-8'), " : ", change_cam.macAddress.hex(), " is NOT AVAILABLE")
                    time.sleep(1)
                    continue
                
            with camerasLock:
               camera = cameras[change_cam.macAddress]   
                
                
            if change_cam.isCompleted() or camera.ip == change_cam.ip:
                   print("ip of camera ", change_cam.name.decode('utf-8'), "already changed to ", change_cam.ip.hex())
                   change_cam.complete()
                   time.sleep(1)
                   continue
            
               
            
            
            respacket = camera.changeIp(change_cam.ip, change_cam.name,params["_MASKNEW_"],params["_GWNEW_"],params["_DNS1NEW_"],params["_DNS2NEW_"],params["_AUTH_"],params["new_Const1"], params["newDHCP"])
       #     print(camera.name)
       #     print(request.name)
                
       #     print(camera.ip)
       #     print(request.ip)
             
      #      camera.name = request.name
       #     camera.ip = request.ip
       #     camera.defGW = params["_GWNEW_"]
       ##     camera.mask = params["_MASKNEW_"]
        #    camera.dns1 = params["_DNS1NEW_"]
        #    camera.dns2 = params["_DNS2NEW_"]
        #    camera.auth = params["_AUTH_"]
              
        #    print(camera.name)
        #    print(camera.ip)
            
            
            
         
            print(camera.respacket.hex())
            s.sendto(camera.respacket, (udp_ip, udp_port))
            print("ip of camera", change_cam.name.decode('utf-8'), " changed from ", camera.ip.hex(), " to ", change_cam.ip.hex())
            change_cam.complete()
            
            time.sleep(1)
        
    s.close()
        

def send_pack(
    IPsourceaddress,
    udp_ip,
    udp_port,
    def_pack
):
    print(IPsourceaddress + " : " + str(udp_port))
    server_address = (IPsourceaddress, udp_port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.connect(server_address)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 20)
    print("UDP target IP: " + udp_ip)
    print("UDP target port:" + str(udp_port))
    
    while True:
        
        byte = bytes.fromhex(def_pack)
        print("Muticast Packet Send")    
        s.sendto(byte, (udp_ip, udp_port))
        time.sleep(10)
    s.close()
    
    
def receive_pack(
        
    IPsourceaddress,
    ip_addr,
    udp_port,
    UDP_IP_SEND,
    DEFAULT_PACK,
    cameras,
    camerasLock
):
    
    server_address = (IPsourceaddress, udp_port)

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind(server_address)
    group = socket.inet_aton(ip_addr)
    mreq = struct.pack('4sL', group, socket.INADDR_ANY)
    udp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    
       
    #Бесконечный цикл работы программы
    
    while True:
        data = udp_socket.recv(1024)
        #print(data.hex())
   #     print(len(data))
        if len(data) != 240:
            print("ERROR Length Packet")
            continue
        with camerasLock:
            camera = Camera.fromData(data)
            if not camera.macAddress in cameras:
                cameras[camera.macAddress] = camera
       #         print(cameras)
                print(len(cameras))
                print("\r")
                for a,b in cameras.items():
    #                print(b.name)
                    pass
        if not data:
            break

     #   time.sleep(0.1)
   #     print(len(cameras), end='')
  
    udp_socket.close()

def main():
    
    
    DEFAULT_PACK = "4d48454407000100010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    UDP_IP_SEND = "234.55.55.55"
    UDP_IP_RECEIVE = "234.55.55.56"
    UDP_PORT = 23456
    newConst1 = '4d4845440700010003000000'
    dhcp_dis = '00000000'
    CamIPFile = "cams_example.csv"
    CamsParamsFile = "cams_param_example.conf"
    interface = 'Ethernet'
    IPsourceaddress = "172.17.57.200"
    params = {}
    receivepacketfile = "receive.packet"
    f = open(CamsParamsFile)
    Lines = f.readlines()
    f.close()
    
    params = {}
    lst_line ={}
    
    for Linestr in Lines:
        (a,b) =  Linestr.split()
        
        byte_b = convert2byte(b)
        params[a] = byte_b
    
    byte_newConst1 = convert2byte(newConst1)
    byte_newDHCP = convert2byte(dhcp_dis)
    params["new_Const1"] = byte_newConst1
    params["newDHCP"] = byte_newDHCP
   # print(params)
  #  print(params)      #  Разобрали файл с одинаковыми параметрами для камер
  
  
  ###Нужно перегнать в правильную форму в байтовую все значения
    
    
    
    change_cams = readRequestsFromFile(CamIPFile) # Разобрали файл с камерами для настройки
    for camsreq in change_cams:
        
 #       print(str(camsreq.ip) + "\t" + str(camsreq.name) + "\t" + str(camsreq.macAddress))
        pass
    
    
    
    #Auth = "0x14d54497a4e445532"
    #NAME =   # Строгой длины 15 символол 
    #DATAPORT # Перевернуты попарно симоволы в шеснадцаричной системе
    #SERIAL #  6 символов читаются попарно с конца
    
    #MESSAGE = "0x4d4845440700010003000000" + NAME + "0x0000000000" + MAC + DATAPORT + IP + MASK + DefGW + Const1 + Auth + "0x0000000000000000000000000000000000000000" + DNS1 + DNS2 + SERIAL + "0x0000000000" + IPLOCAL + MASKLOCAL
    
    camerasLock = threading.Lock()
    
    cameras = {}
    
    
    receivingThread = threading.Thread(target=lambda: receive_pack(IPsourceaddress, UDP_IP_RECEIVE,UDP_PORT,UDP_IP_SEND, DEFAULT_PACK, cameras, camerasLock), daemon = True)
    receivingThread.start()

   
  #  f = open(receivepacketfile)
  #  packet = f.read()
  #  f.close()
    
  #  packet = packet.strip()
  #  packetbyte = bytes.fromhex(packet)
   # camera = Camera.fromData(packetbyte)
    
    
    
    sendingThread = threading.Thread(target=lambda: send_pack(IPsourceaddress, UDP_IP_SEND, UDP_PORT, DEFAULT_PACK), daemon = True)
    sendingThread.start()
    
    
        
    
    
    changeIpThread = threading.Thread(target=lambda: change_ip(IPsourceaddress, UDP_IP_SEND, UDP_PORT, cameras, camerasLock, change_cams, params), daemon = True)
    changeIpThread.start()
    
    input("Press ENTER to STOP.....\n")
  
    receivingThread.join()
    sendingThread.join()
    changeIpThread.join()
    
    
if __name__ == '__main__':
  main()