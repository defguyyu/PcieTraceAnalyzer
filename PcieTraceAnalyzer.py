import csv, math

strInputFilename = 'PcieTrace.csv'
strOutputFilename = 'PcieTrace.log'

adminQueueBaseAddress = 0
adminQueueSize = 0

barAddress = 0xDF000000

# Queue Id, SQ Base Address, SQ Size, CQ Base Address, CQ Size, SQ Tail Doorbell, CQ Head Doorbell, SQ Head Pointer
QueueTable = [
    #   Qid,  SqBase,   SqSize, CqBase,     CqSize, SqTdbl, CqHdbl, SqHptr
        #[0,     0,      0x100,         0,      0,      0,      0,      0],
        #[1,     0,      0x20,          0,      0,      0,      0,      0],
        #[2,     0,      0x100,         0,      0,      0,      0,      0],
        #[3,     0,      0x20,          0,      0,      0,      0,      0],
        [4, 0x4F1E0000,  0x100, 0x50340000,    0x100,    0,      0,      0],
        [5, 0x4F200000,  0x100, 0x4F1F0000,    0x100,    0,      0,      0],
        [6, 0x4f220000,  0x10,  0x4F210000,     0x10,    0,      0,      0]]
        

fieldNames = ['PACKET', 'DESCRIPTION', 'QTYPE', 'QID', 'ADDRESS', 'DOORBELL', 'OPCODE', 'CID', 'NSPACE', 'LBA', 'NLB', 'SQHD', 'DATA']

fileInput = open(strInputFilename, newline='')
csvReader = csv.DictReader(fileInput)

fileOutput = open(strOutputFilename, 'w', newline = '')
csvWriter = csv.DictWriter(fileOutput, fieldnames = fieldNames)

pendingCommand = False
savTlpType = ""
savQueueId = -1
savQueueType = -1
savDescription = ""
savAddress = 0

numberOfLines = 0
cMaxNumberOfLines = 1000
csvWriter.writeheader()
for row in csvReader:
    nvmePacketType = 0xFFFF # Invalid
    
    address = 0;
    if(row['Address']!=''):
        address = int(row['Address'].replace(':',''), 16)
    description = ""
    linkDir = row['Link Dir'].replace('stream','')
    dllpType = row['DLLP Type']
    tlpType = row['TLP Type']
    psn = row['PSN']
    ackNakSeqNum = row['AckNak_Seq_Num']
    
    queueId = -1
    queueType = -1
    doorbell = ""
    opCode = 0
    cid = 0
    nspace = 0
    lba = 0
    nlb = 0
    sqhd = 0
    data = row['DATA']
    
    if(barAddress <= address < barAddress + 0x1000):
        nvmePacketType = 0 # NVMe Controller Registers

    # Doorbell checking
    if( barAddress+0x1000 <= address < barAddress + 0x2000):
        if( (row['Length'] == '1') and (row['TLP Type'] == 'MWr(32)')):
            queueId = math.floor((address - (barAddress+0x1000)) / 8)
            # if(data.find('E') != -1): doorbell = 0xFFFF
            # else: doorbell = int(data, 16)
            doorbell = data
            if( (address - (barAddress+0x1000)) % 8 == 0 ):
                queueType = 0 # SQ
                nvmePacketType = 1 # NVME SQ Tail Doorbell
            else:
                queueType = 1 # CQ
                nvmePacketType = 2 # NVME CQ Head Doorbell
            if(queueType == 0):
                description = "SQ " + str(queueId) + " TDBL " + doorbell[4:]
            else:
                description = "CQ " + str(queueId) + " HDBL " + doorbell[4:]
                
    # SQ Command checking
    sizeOfIoSqEntry = 0x40
    for queue in QueueTable:
        # SQ check
        if(queue[1]!=0 and queue[1] <= address < queue[1]+queue[2]*sizeOfIoSqEntry):
            queueId = queue[0];
            queueType = 0 # SQ
            nvmePacketType = 103 # NVME SQ Command pending
            description = "SQ " + str(queueId) + " CMND "
            
            pendingCommand = True
            savQueueId = queueId
            savQueueType = queueType
            savDescription = description
            savAddress = address
            savTlpType = tlpType

    # Pending Command checking
    if(tlpType == 'CplD' and pendingCommand == True):
        nvmePacketType = 3 # NVME SQ Command
        pendingCommand = False
        queueId= savQueueId
        queueType = savQueueType
        address = savAddress
        tlpType = savTlpType + '-' + tlpType
        opCode = data[4:8]
        cid = data[0:4]
        nspace = data[1*(8+1):1 * (8+1)+8]
        lba = data[11*(8+1):11 * (8+1)+8] + data[10*(8+1):10 * (8+1)+8]
        nlb = data[12*(8+1):12 * (8+1)+8]
        description = savDescription + cid

    # CQE checking
    sizeOfCqEntry = 0x10
    for queue in QueueTable:
        if(queue[3]!=0 and queue[3] <= address < queue[3]+queue[4]*sizeOfCqEntry):
            queueId = queue[0]
            queueType = 1 # CQ
            nvmePacketType = 4 # NVME CQE
            sqhd = data[2 * (8+1)+4:2 * (8+1)+8]
            cid = data[3 * (8+1)+4:3 *(8+1)+8]
            description = "CQ " + str(queueId) + " CQE  " + cid


    if(pendingCommand != True and dllpType != 'ACK' and nvmePacketType < 100):
        print('{:^7}{:5}{:4}{:12}{:>5}{:>5}{:16}{:>10X}{:>10}{:>5}{:>5}{:>9}{:>17}{:>9}{:>9},{:24}'.format(row['Packet'], linkDir, dllpType, tlpType, psn, ackNakSeqNum, description, address, doorbell, opCode, cid, nspace, lba, nlb, sqhd, data[:9*8]))
        if(queueType == 0) : qTypeStr = "SQ"
        else: qTypeStr = "CQ"
        #fieldNames = ['PACKET', 'DESCRIPTION', 'QTYPE', 'QID', 'ADDRESS', 'DOORBELL', 'OPCODE', 'CID', 'NSPACE', 'LBA', 'NLB', 'SQHD', 'DATA']

        csvWriter.writerow({'PACKET': row['Packet'], 'DESCRIPTION':description, 'QTYPE':qTypeStr, 'QID':queueId, 'ADDRESS':address, 'DOORBELL':doorbell, 'OPCODE': opCode, 'CID':cid, 'NSPACE':nspace, 'LBA':lba, 'NLB':nlb, 'SQHD':sqhd, 'DATA':data})
    
fileInput.close()
fileOutput.close()
