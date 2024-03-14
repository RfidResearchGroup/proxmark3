#   Benjamin DELPY `gentilkiwi`
#   https://blog.gentilkiwi.com/
#   benjamin@gentilkiwi.com
#
#   Basic script to try to interpret Intertic data on ST25TB / SRT512 in french transports
#   For Proxmark3 with love <3
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   See LICENSE.txt for the text of the license.

import sys, os
from datetime import datetime, timedelta
from bitarray import bitarray
from bitarray.util import ba2int

class BitMe:
    def __init__(self):
        self.data = bitarray()
        self.idx = 0

    def addBits(self, bits):
        self.data += bits

    def addBytes(self, bytes):
        self.data.frombytes(bytes)

    def nom_bits(self, cb):
        ret = self.data[self.idx:self.idx + cb]
        self.idx += cb
        return ret

    def nom(self, cb):
        return ba2int(self.nom_bits(cb))

    def nom_bits_left(self):
        return self.data[self.idx:None]

    def isEmpty(self):
        return (len(self.data) == 0)


ISO_Countries = {
    0x250: 'France',
}


FRA_OrganizationalAuthority_Contract_Provider = {
    0x000: {
        5: 'Lille (Ilévia / Keolis)',
        7: 'Lens-Béthune (Tadao / Transdev)',
    },
    0x006: {
        1: 'Amiens (Ametis / Keolis)',
    },
    0x008: {
        15: 'Angoulême (STGA)',
    },
    0x021: {
        1: 'Bordeaux (TBM / Keolis)',
    },
    0x072: {
        1: 'Tours (filbleu / Keolis)',
    },
    0x078: {
        4: 'Reims (Citura / Transdev)',
    },
    0x502: {
        83: 'Annecy (Sibra)',
    },
    0x091: {
        1: 'Strasbourg (CTS)',
    },
    0x907: {
        1: 'Dijon (Divia / Keolis)',
    },
    0x908: {
        1: 'Rennes (STAR / Keolis)',
    },
    0x912: {
        3: 'Le Havre (Lia / Transdev)',
        35: 'Cherbourg-en-Cotentin (Cap Cotentin / Transdev)',
    },
    0x913: {
        3: 'Nîmes (Tango / Transdev)',
    },
    0x917: {
        4: 'Angers (Irigo / RATP)',
        7: 'Saint-Nazaire (Stran)',
    },
}


def main():

    print('Basic script to try to interpret Intertic data on ST25TB / SRT512 in french transports')
    print('--------------------------------------------------------------------------------------\n')

    if(len(sys.argv) != 2):
        print('\tUsage  : {0} <dumpfile.bin>\n\tExample: {0} hf-14b-D00233787DFBB4D5-dump.bin\n'.format(sys.argv[0]))
        return 1

    binaryDumpFileName = sys.argv[1]

    data = BitMe()

    print('Using \'{}\' as binary dump file...'.format(binaryDumpFileName))
    file = open(binaryDumpFileName, mode='rb')

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0, os.SEEK_SET)

    if (size != 68):
        print('\'{}\' file size is not 68 bytes'.format(binaryDumpFileName))
        return 2

    while True:
        chunk = file.read(4)
        if not chunk:
            break
        data.addBytes(chunk[::-1])

    file.close()

    SystemArea = BitMe()
    Distribution_Data = BitMe()
    C1 = BitMe()
    C2 = BitMe()
    Usage_Sta_B = BitMe()
    Usage_Sta_E = BitMe()
    Usage_Data = BitMe()
    Usage_Cer = BitMe()
    Distribution_Cer = BitMe()


    Distribution_Data_End = data.nom_bits(24)
    SystemArea.addBits(data.nom_bits(8))

    PID = SystemArea.nom(5)
    bIsFlipFlop = PID & 0x10
    KeyId = SystemArea.nom(3)

    print()
    print('PID (product): 0x{:02x} (flipflop?: {})'.format(PID, bIsFlipFlop));
    print('KeyId        :', hex(KeyId));

    match PID:

        case 0x02:
            Distribution_Data.addBits(data.nom_bits(3 * 32))
            Usage_Data_End = data.nom_bits(30)
            Usage_Sta_B.addBits(data.nom_bits(2))
            C1.addBits(data.nom_bits(32))
            C2.addBits(data.nom_bits(32))
            Usage_Data.addBits(data.nom_bits(7 * 32))
            Usage_Data.addBits(Usage_Data_End)
            Usage_Data.addBits(data.nom_bits(14))
            Usage_Sta_E.addBits(data.nom_bits(2))
            Usage_Cer.addBits(data.nom_bits(16))
            Distribution_Cer.addBits(data.nom_bits(32))

        case 0x06:
            Distribution_Data.addBits(data.nom_bits(4 * 32))
            C1.addBits(data.nom_bits(32))
            C2.addBits(data.nom_bits(32))
            Distribution_Data.addBits(data.nom_bits(3 * 32))
            Distribution_Data.addBits(Distribution_Data_End)
            Usage_Data_End = data.nom_bits(30)
            Usage_Sta_B.addBits(data.nom_bits(2))
            Usage_Data.addBits(data.nom_bits(3 * 32))
            Usage_Data.addBits(Usage_Data_End)
            Usage_Data.addBits(data.nom_bits(14))
            Usage_Sta_E.addBits(data.nom_bits(2))
            Usage_Cer.addBits(data.nom_bits(16))
            Distribution_Cer.addBits(data.nom_bits(32))

        case 0x07:
            Distribution_Data.addBits(data.nom_bits(4 * 32))
            C1.addBits(data.nom_bits(32))
            C2.addBits(data.nom_bits(32))
            Distribution_Data.addBits(data.nom_bits(4 * 32))
            Distribution_Data.addBits(Distribution_Data_End)
            Usage_Data_End = data.nom_bits(30)
            Usage_Sta_B.addBits(data.nom_bits(2))
            Usage_Data.addBits(data.nom_bits(3 * 32))
            Usage_Data.addBits(Usage_Data_End)
            Usage_Data.addBits(data.nom_bits(14))
            Usage_Sta_E.addBits(data.nom_bits(2))
            Usage_Cer.addBits(data.nom_bits(16))
            Distribution_Cer.addBits(data.nom_bits(32))

        case 0x0a:
            Distribution_Data.addBits(data.nom_bits(4 * 32))
            C1.addBits(data.nom_bits(32))
            C2.addBits(data.nom_bits(32))
            Distribution_Data.addBits(data.nom_bits(8 * 32))
            Distribution_Data.addBits(Distribution_Data_End)
            Distribution_Cer.addBits(data.nom_bits(32))
            # No USAGE for 0x0a

        case 0x0b: # Not in the draft :(
            Distribution_Data.addBits(data.nom_bits(4 * 32))
            C1.addBits(data.nom_bits(32))
            C2.addBits(data.nom_bits(32))
            Distribution_Data.addBits(data.nom_bits(8 * 32))
            Distribution_Data.addBits(Distribution_Data_End)
            Distribution_Cer.addBits(data.nom_bits(32))

        case _:
            print('PID not (yet?) supported')
            return 3

    '''
    DISTRIBUTION
    ------------
    Not very well documented but seems standard for this part
    '''

    ContractNetworkId = Distribution_Data.nom_bits(24)
    CountryCode = ba2int(ContractNetworkId[0:0+12])
    OrganizationalAuthority = ba2int(ContractNetworkId[12:12+12])

    ContractApplicationVersionNumber = Distribution_Data.nom(6)
    ContractProvider = Distribution_Data.nom(8)
    ContractTariff = Distribution_Data.nom(16)
    ContractMediumEndDate = Distribution_Data.nom(14)

    Distribution_left = Distribution_Data.nom_bits_left()

    RELOADING1 = C1.nom(8)
    COUNTER1 = C1.nom(24)
    RELOADING2 = C2.nom(8)
    COUNTER2 = C2.nom(24)

    '''
    USAGE
    -----
    No documentation about Usage
    All is left
    '''
    Usage_left = Usage_Data.nom_bits_left()

    if not Distribution_Data.isEmpty():
        print()
        print('DISTRIBUTION')
        print('  CountryCode                     : {:03x} - {}'.format(CountryCode, ISO_Countries.get(CountryCode, '?')));
        print('  OrganizationalAuthority         : {:03x}'.format(OrganizationalAuthority));
        print('  ContractApplicationVersionNumber:', ContractApplicationVersionNumber);
        print('  ContractProvider                :', ContractProvider);
        if (CountryCode == 0x250):
            oa = FRA_OrganizationalAuthority_Contract_Provider.get(OrganizationalAuthority)
            if (oa is not None):
                s = oa.get(ContractProvider)
                if (s is not None):
                    print('      ~ Authority & Provider ~    :', s)
        print('  ContractTariff                  :', ContractTariff);
        print('  ContractMediumEndDate           : {} ({})'.format(ContractMediumEndDate, (datetime(1997, 1, 1) + timedelta(days = ContractMediumEndDate)).strftime('%Y-%m-%d')));
        print('  left...                         :', Distribution_left);
        print('  [CER] Distribution              : {:08x}'.format(Distribution_Cer.nom(32)))

    print()
    print('COUNTER')
    print('  [1] Counter: 0x{:06x} - Reloading available 0x{:02x}'.format(COUNTER1, RELOADING1))
    print('  [2] Counter: 0x{:06x} - Reloading available 0x{:02x}'.format(COUNTER2, RELOADING2))

    if not Usage_Data.isEmpty():
        print()
        print('USAGE')

        print('  left...                         :', Usage_left);
        print('  [CER] Usage                     : {:04x}'.format(Usage_Cer.nom(16)))

    return 0


if __name__ == '__main__':
    sys.exit(main())
