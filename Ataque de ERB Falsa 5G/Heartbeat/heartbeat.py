#Projeto Fake-Base-Station-5G
#Criado por Roger W. Coêlho
#Código Heartbeat para informar o Heartbeat_info ao Núcleo do 5G (Open5GS)

import socket
import time
import struct


#Classe Heartbeat Projeto Fake-Base-Station-5G
class Heartbeat:

    #Função para Heartbeat_info Cliente
    def heartbeat_info_client(target, dst):

        id = 512
        id_heartbeat = id.to_bytes(2, 'big')
        port_dst = dst.to_bytes(2, 'big')
        ip_dst = socket.inet_aton(target)
        valor = 0
        zero = valor.to_bytes(2, 'big')
        tempo_local = time.localtime()
        bytes_tempo = struct.pack('iiii',
                         tempo_local.tm_sec,
                         tempo_local.tm_min,
                         tempo_local.tm_hour,
                         tempo_local.tm_mday)

        heartbeat_info = id_heartbeat + port_dst + ip_dst + (zero * 10) + bytes_tempo + (zero * 4)     

        return heartbeat_info  

        
    #Função para Heartbeat_info Multihoming
    def heartbeat_info_multihoming(target, target1, dst):
        
        id = 512
        id_heartbeat = id.to_bytes(2, 'big')
        port_dst = dst.to_bytes(2, 'big')
        ip_dst = socket.inet_aton(target)
        valor = 0
        zero = valor.to_bytes(2, 'big')
        tempo_local = time.localtime()
        bytes_tempo = struct.pack('iiii',
                         tempo_local.tm_sec,
                         tempo_local.tm_min,
                         tempo_local.tm_hour,
                         tempo_local.tm_mday)
        print("Converter: ",bytes_tempo)


        heartbeat_info = id_heartbeat + port_dst + ip_dst + (zero * 10) + bytes_tempo + (zero * 4)     

        print("Classe: ",heartbeat_info) 

        return heartbeat_info   