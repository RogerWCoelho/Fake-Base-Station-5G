#Projeto Fake-Base-Station-5G
#Criado por Roger W. Coêlho
#Código NGAP para conexão entre a ERB falsa e o Núcleo 5G

from scapy.all import *
from pycrate_asn1dir.NGAP import *
#from pycrate_mobile.NAS import *

#Classe NGAP Setup Request ERB
class NGSetupRequest(Packet): 

    PDU = NGAP_PDU_Descriptions.NGAP_PDU

    IEs = []

    IEs.append({'id': 27, 'criticality': 'reject', 'value': (
        'GlobalRANNodeID', ('globalGNB-ID', {'pLMNIdentity': b'\x99\xf9\x07', 'gNB-ID': ('gNB-ID', (1, 32))}))})
    
    IEs.append({'id': 82, 'criticality': 'ignore', 'value': ('RANNodeName', 'Falsa-ERB')})
    IEs.append({'id': 102, 'criticality': 'reject', 'value': ('SupportedTAList', [{'tAC': b'\x00\x00\x01',
                                                                                   'broadcastPLMNList': [
                                                                                       {'pLMNIdentity': b'\x99\xf9\x07',
                                                                                        'tAISliceSupportList': [{
                                                                                            's-NSSAI': {
                                                                                                'sST': b'\x01'}}]}]}])})

    IEs.append({'id': 21, 'criticality': 'ignore', 'value': ('PagingDRX', 'v128')})


    val = (
        'initiatingMessage',
        {'procedureCode': 21, 'criticality': 'reject', 'value': ('NGSetupRequest', {'protocolIEs': IEs})}) 
    

    PDU.set_val(val)

    PDU_NGSetupResquest = PDU.to_aper()

    Name = "NG Application Protocol (NGSetupRequest)"