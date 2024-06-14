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
from typing import NamedTuple

class BitMe:
    def __init__(self):
        self.data = bitarray(endian = 'big')
        self.idx = 0

    def reset(self):
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

'''
A generic Describe_Usage function with variable number of bits between stamps will be more optimal
At this time I want to keep more places/functions to try to parse other fields in 'unk1' and 'left'
'''

TYPE_EventCode_Nature = {
    0x1: 'urban bus',
    0x2: 'interurban bus',
    0x3: 'metro',
    0x4: 'tramway',
    0x5: 'train',
    0x8: 'parking',
}

TYPE_EventCode_Type = {
    0x1: 'entry validation',
    0x2: 'exit validation',
    0x4: 'ticket inspecting',
    0x6: 'connection entry validation',
    0x14: 'test validation',
    0x15: 'connection exit validation',
    0x16: 'canceled validation',
    0x17: 'invalidation',
    0x18: 'distribution',
}

TYPE_EventGeoRoute_Direction = {
    0: 'undefined',
    1: 'outward',
    2: 'inward',
    3: 'circular',
}

def Describe_Usage_1(Usage, ContractMediumEndDate, Certificate):
    EventDateStamp = Usage.nom(10)
    EventTimeStamp = Usage.nom(11)
    unk = Usage.nom_bits(65)
    EventValidityTimeFirstStamp = Usage.nom(11)
    
    print('  EventDateStamp             : {} ({})'.format(EventDateStamp, (datetime(1997, 1, 1) + timedelta(days = ContractMediumEndDate - EventDateStamp)).strftime('%Y-%m-%d')));
    print('  EventTimeStamp             : {} ({:02d}:{:02d})'. format(EventTimeStamp, EventTimeStamp // 60, EventTimeStamp % 60))
    print('  unk1...                    :', unk);
    print('  EventValidityTimeFirstStamp: {} ({:02d}:{:02d})'. format(EventValidityTimeFirstStamp, EventValidityTimeFirstStamp // 60, EventValidityTimeFirstStamp % 60))
    print('  left...                    :', Usage.nom_bits_left());
    print('  [CER] Usage                : {:04x}'.format(Certificate.nom(16)))

def Describe_Usage_1_1(Usage, ContractMediumEndDate, Certificate):
    EventDateStamp = Usage.nom(10)
    EventTimeStamp = Usage.nom(11)
    unk0 = Usage.nom_bits(8)
    EventCode_Nature  = Usage.nom(5)
    EventCode_Type  = Usage.nom(5)
    unk1 = Usage.nom_bits(11)
    EventGeoVehicleId = Usage.nom(16)
    EventGeoRouteId = Usage.nom(14)
    EventGeoRoute_Direction = Usage.nom(2)
    EventCountPassengers_mb = Usage.nom(4)
    EventValidityTimeFirstStamp = Usage.nom(11)
    
    print('  DateStamp             : {} ({})'.format(EventDateStamp, (datetime(1997, 1, 1) + timedelta(days = ContractMediumEndDate - EventDateStamp)).strftime('%Y-%m-%d')));
    print('  TimeStamp             : {} ({:02d}:{:02d})'. format(EventTimeStamp, EventTimeStamp // 60, EventTimeStamp % 60))
    print('  unk0...               :', unk0);
    print('  Code/Nature           : 0x{:x} ({})'.format(EventCode_Nature, TYPE_EventCode_Nature.get(EventCode_Nature, '?')))
    print('  Code/Type             : 0x{:x} ({})'.format(EventCode_Type, TYPE_EventCode_Type.get(EventCode_Type, '?')))
    print('  unk1...               :', unk1);
    print('  GeoVehicleId          : {}'. format(EventGeoVehicleId))
    print('  GeoRouteId            : {}'. format(EventGeoRouteId))
    print('  Direction             : {} ({})'. format(EventGeoRoute_Direction, TYPE_EventGeoRoute_Direction.get(EventGeoRoute_Direction, '?')))
    print('  Passengers(?)         : {}'. format(EventCountPassengers_mb))
    print('  ValidityTimeFirstStamp: {} ({:02d}:{:02d})'. format(EventValidityTimeFirstStamp, EventValidityTimeFirstStamp // 60, EventValidityTimeFirstStamp % 60))
    print('  left...               :', Usage.nom_bits_left());
    print('  [CER] Usage           : {:04x}'.format(Certificate.nom(16)))

def Describe_Usage_1_2(Usage, ContractMediumEndDate, Certificate):
    EventDateStamp = Usage.nom(10)
    EventTimeStamp = Usage.nom(11)
    EventCount_mb = Usage.nom(6)
    unk0 = Usage.nom_bits(4)
    EventCode_Nature_mb  = Usage.nom(4)
    EventCode_Type_mb  = Usage.nom(4)
    unk1 = Usage.nom_bits(11)
    EventGeoVehicleId = Usage.nom(16)
    EventGeoRouteId = Usage.nom(14)
    EventGeoRoute_Direction = Usage.nom(2)
    EventCountPassengers_mb = Usage.nom(4)
    EventValidityTimeFirstStamp = Usage.nom(11)
    
    TYPE_EventCode_Nature_Reims = { # usually it's the opposite, but ... ?
        0x4: 'urban bus',
        0x1: 'tramway',
    }
    
    print('  DateStamp             : {} ({})'.format(EventDateStamp, (datetime(1997, 1, 1) + timedelta(days = ContractMediumEndDate - EventDateStamp)).strftime('%Y-%m-%d')));
    print('  TimeStamp             : {} ({:02d}:{:02d})'. format(EventTimeStamp, EventTimeStamp // 60, EventTimeStamp % 60))
    print('  Count(?)              : {}'. format(EventCount_mb))
    print('  unk0...               :', unk0);
    print('  Code/Nature(?)        : 0x{:x} ({})'.format(EventCode_Nature_mb, TYPE_EventCode_Nature_Reims.get(EventCode_Nature_mb, '?')))
    print('  Code/Type(?)          : 0x{:x} ({})'.format(EventCode_Type_mb, TYPE_EventCode_Type.get(EventCode_Type_mb, '?')))
    print('  unk1...               :', unk1);
    print('  GeoVehicleId          : {}'. format(EventGeoVehicleId))
    print('  GeoRouteId            : {}'. format(EventGeoRouteId))
    print('  Direction             : {} ({})'. format(EventGeoRoute_Direction, TYPE_EventGeoRoute_Direction.get(EventGeoRoute_Direction, '?')))
    print('  Passengers(?)         : {}'. format(EventCountPassengers_mb))
    print('  ValidityTimeFirstStamp: {} ({:02d}:{:02d})'. format(EventValidityTimeFirstStamp, EventValidityTimeFirstStamp // 60, EventValidityTimeFirstStamp % 60))
    print('  left...               :', Usage.nom_bits_left());
    print('  [CER] Usage           : {:04x}'.format(Certificate.nom(16)))


def Describe_Usage_2(Usage, ContractMediumEndDate, Certificate):
    EventDateStamp = Usage.nom(10)
    EventTimeStamp = Usage.nom(11)
    unk0 = Usage.nom_bits(8)
    EventCode_Nature  = Usage.nom(5)
    EventCode_Type  = Usage.nom(5)
    unk1 = Usage.nom_bits(11)
    EventGeoRouteId = Usage.nom(14)
    EventGeoRoute_Direction = Usage.nom(2)
    EventCountPassengers_mb = Usage.nom(4)
    EventValidityTimeFirstStamp = Usage.nom(11)
    
    print('  DateStamp             : {} ({})'.format(EventDateStamp, (datetime(1997, 1, 1) + timedelta(days = ContractMediumEndDate - EventDateStamp)).strftime('%Y-%m-%d')));
    print('  TimeStamp             : {} ({:02d}:{:02d})'. format(EventTimeStamp, EventTimeStamp // 60, EventTimeStamp % 60))
    print('  unk0...               :', unk0);
    print('  Code/Nature           : 0x{:x} ({})'.format(EventCode_Nature, TYPE_EventCode_Nature.get(EventCode_Nature, '?')))
    print('  Code/Type             : 0x{:x} ({})'.format(EventCode_Type, TYPE_EventCode_Type.get(EventCode_Type, '?')))
    print('  unk1...               :', unk1);
    print('  GeoRouteId            : {}'. format(EventGeoRouteId))
    print('  Direction             : {} ({})'. format(EventGeoRoute_Direction, TYPE_EventGeoRoute_Direction.get(EventGeoRoute_Direction, '?')))
    print('  Passengers(?)         : {}'. format(EventCountPassengers_mb))
    print('  ValidityTimeFirstStamp: {} ({:02d}:{:02d})'. format(EventValidityTimeFirstStamp, EventValidityTimeFirstStamp // 60, EventValidityTimeFirstStamp % 60))
    print('  left...               :', Usage.nom_bits_left());
    print('  [CER] Usage           : {:04x}'.format(Certificate.nom(16)))
    
def Describe_Usage_3(Usage, ContractMediumEndDate, Certificate):
    EventDateStamp = Usage.nom(10)
    EventTimeStamp = Usage.nom(11)
    unk = Usage.nom_bits(27)
    EventValidityTimeFirstStamp = Usage.nom(11)
    
    print('  EventDateStamp             : {} ({})'.format(EventDateStamp, (datetime(1997, 1, 1) + timedelta(days = ContractMediumEndDate - EventDateStamp)).strftime('%Y-%m-%d')));
    print('  EventTimeStamp             : {} ({:02d}:{:02d})'. format(EventTimeStamp, EventTimeStamp // 60, EventTimeStamp % 60))
    print('  unk1...                    :', unk);
    print('  EventValidityTimeFirstStamp: {} ({:02d}:{:02d})'. format(EventValidityTimeFirstStamp, EventValidityTimeFirstStamp // 60, EventValidityTimeFirstStamp % 60))
    print('  left...                    :', Usage.nom_bits_left());
    print('  [CER] Usage                : {:04x}'.format(Certificate.nom(16)))
    
def Describe_Usage_4(Usage, ContractMediumEndDate, Certificate):
    EventDateStamp = Usage.nom(10)
    EventTimeStamp = Usage.nom(11)
    unk = Usage.nom_bits(63)
    EventValidityTimeFirstStamp = Usage.nom(11)
    
    print('  EventDateStamp             : {} ({})'.format(EventDateStamp, (datetime(1997, 1, 1) + timedelta(days = ContractMediumEndDate - EventDateStamp)).strftime('%Y-%m-%d')));
    print('  EventTimeStamp             : {} ({:02d}:{:02d})'. format(EventTimeStamp, EventTimeStamp // 60, EventTimeStamp % 60))
    print('  unk1...                    :', unk);
    print('  EventValidityTimeFirstStamp: {} ({:02d}:{:02d})'. format(EventValidityTimeFirstStamp, EventValidityTimeFirstStamp // 60, EventValidityTimeFirstStamp % 60))
    print('  left...                    :', Usage.nom_bits_left());
    print('  [CER] Usage                : {:04x}'.format(Certificate.nom(16)))

def Describe_Usage_Generic(Usage, ContractMediumEndDate, Certificate):
    print('  !!! GENERIC DUMP - please provide full file dump to benjamin@gentilkiwi.com - especially if NOT empty !!!')
    print('  left...                    :', Usage.nom_bits_left());
    print('  [CER] Usage                : {:04x}'.format(Certificate.nom(16)))
    print('  !!! Trying Usage_1 (the most common) !!!')
    Usage.reset()
    Certificate.reset()
    Describe_Usage_1(Usage, ContractMediumEndDate, Certificate)

class InterticHelper(NamedTuple):
    OrganizationalAuthority: str
    ContractProvider: str
    UsageDescribeFunction: callable = None

ISO_Countries = {
    0x250: 'France',
}

FRA_OrganizationalAuthority_Contract_Provider = {
    0x000: {
        5: InterticHelper('Lille', 'Ilévia / Keolis', Describe_Usage_1_1),
        7: InterticHelper('Lens-Béthune', 'Tadao / Transdev', Describe_Usage_1_1),
    },
    0x006: {
        1: InterticHelper('Amiens', 'Ametis / Keolis'),
    },
    0x008: {
        15: InterticHelper('Angoulême', 'STGA', Describe_Usage_1_1), # May have a problem with date ?
    },
    0x021: {
        1: InterticHelper('Bordeaux', 'TBM / Keolis', Describe_Usage_1_1),
    },
    0x057: {
        1: InterticHelper('Lyon', 'TCL / Keolis', Describe_Usage_1), # Strange usage ?, kept on generic 1
    },
    0x072: {
        1: InterticHelper('Tours', 'filbleu / Keolis', Describe_Usage_1_1),
    },
    0x078: {
        4: InterticHelper('Reims', 'Citura / Transdev', Describe_Usage_1_2),
    },
    0x091: {
        1: InterticHelper('Strasbourg', 'CTS', Describe_Usage_4), # More dump needed, not only tram !
    },
    0x502: {
        83: InterticHelper('Annecy', 'Sibra', Describe_Usage_2),
        10: InterticHelper('Clermont-Ferrand', 'T2C'),
    },
    0x907: {
        1: InterticHelper('Dijon', 'Divia / Keolis'),
    },
    0x908: {
        1: InterticHelper('Rennes', 'STAR / Keolis', Describe_Usage_2),
        8: InterticHelper('Saint-Malo', 'MAT / RATP', Describe_Usage_1_1),
    },
    0x911: {
        5: InterticHelper('Besançon', 'Ginko / Keolis'),
    },
    0x912: {
        3: InterticHelper('Le Havre', 'Lia / Transdev', Describe_Usage_1_1),
        35: InterticHelper('Cherbourg-en-Cotentin', 'Cap Cotentin / Transdev'),
    },
    0x913: {
        3: InterticHelper('Nîmes', 'Tango / Transdev', Describe_Usage_3),
    },
    0x917: {
        4: InterticHelper('Angers', 'Irigo / RATP', Describe_Usage_1_2),
        7: InterticHelper('Saint-Nazaire', 'Stran'),
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

    Distribution_Data = BitMe()
    Block0Left = BitMe()
    # Usage_DAT = BitMe()
    # Usage_CER = BitMe()
    Usage_A_DAT = BitMe()
    Usage_A_CER = BitMe()
    Usage_B_DAT = BitMe()
    Usage_B_CER = BitMe()
    Distribution_Cer = BitMe()

    SWAP = None
    RELOADING1 = None
    COUNTER1 = None
    # RELOADING2 = None
    # COUNTER2 = None
    Describe_Usage = None

    Block0Left.addBits(data.nom_bits(23))
    KeyId = data.nom(4)
    PID = data.nom(5)

    match PID:
    
        case 0x10:
            Distribution_Data.addBits(data.nom_bits(2 * 32))
            Distribution_Data.addBits(Block0Left.nom_bits_left())
            Usage_A_DAT.addBits(data.nom_bits(2 * 32))
            RELOADING1 = data.nom(8)
            COUNTER1 = data.nom(24)
            SWAP = data.nom(32)
            Usage_A_DAT.addBits(data.nom_bits(2 * 32))
            Usage_A_DAT.addBits(data.nom_bits(16))
            Usage_A_CER.addBits(data.nom_bits(16))
            Usage_B_DAT.addBits(data.nom_bits(4 * 32))
            Usage_B_DAT.addBits(data.nom_bits(16))
            Usage_B_CER.addBits(data.nom_bits(16))
            Distribution_Cer.addBits(data.nom_bits(32))

        case 0x11 | 0x19:
            Distribution_Data.addBits(data.nom_bits(4 * 32))
            Distribution_Data.addBits(Block0Left.nom_bits_left())
            RELOADING1 = data.nom(8)
            COUNTER1 = data.nom(24)
            SWAP = data.nom(32)
            Usage_A_DAT.addBits(data.nom_bits(3 * 32))
            Usage_A_DAT.addBits(data.nom_bits(16))
            Usage_A_CER.addBits(data.nom_bits(16))
            Usage_B_DAT.addBits(data.nom_bits(3 * 32))
            Usage_B_DAT.addBits(data.nom_bits(16))
            Usage_B_CER.addBits(data.nom_bits(16))
            Distribution_Cer.addBits(data.nom_bits(32))
            
        case _:
            print('PID not (yet?) supported: 0x{:02x}'.format(PID))
            return 3


    print('PID (product): 0x{:02x} (flipflop?: {})'.format(PID, (PID & 0x10) != 0));
    print('KeyId        : 0x{:1x}'.format(KeyId))
    print()

    '''
    DISTRIBUTION
    ------------
    Not very well documented but seems standard for this part
    '''
    if not Distribution_Data.isEmpty():

        ContractNetworkId = Distribution_Data.nom_bits(24)
        CountryCode = ba2int(ContractNetworkId[0:0+12])
        OrganizationalAuthority = ba2int(ContractNetworkId[12:12+12])

        ContractApplicationVersionNumber = Distribution_Data.nom(6)
        ContractProvider = Distribution_Data.nom(8)
        ContractTariff = Distribution_Data.nom(16)
        ContractMediumEndDate = Distribution_Data.nom(14)

        Distribution_left = Distribution_Data.nom_bits_left()

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
                    print('      ~ Authority & Provider ~    : {} ({})'.format(s.OrganizationalAuthority, s.ContractProvider))
                    Describe_Usage = s.UsageDescribeFunction
        print('  ContractTariff                  :', ContractTariff);
        print('  ContractMediumEndDate           : {} ({})'.format(ContractMediumEndDate, (datetime(1997, 1, 1) + timedelta(days = ContractMediumEndDate)).strftime('%Y-%m-%d')));
        print('  left...                         :', Distribution_left);
        print('  [CER] Distribution              : {:08x}'.format(Distribution_Cer.nom(32)))
        print()

        if(Describe_Usage is None):
            Describe_Usage = Describe_Usage_Generic
        
        if COUNTER1 is not None:
            print('[1] Counter: 0x{:06x}   - Reloading available: 0x{:02x}'.format(COUNTER1, RELOADING1))
        # if COUNTER2 is not None:
        #    print('[2] Counter: 0x{:06x}   - Reloading available: 0x{:02x}'.format(COUNTER2, RELOADING2))
        if SWAP is not None:
            print('[S] SWAP   : 0x{:08x} - last usage on USAGE_{}'.format(SWAP, 'B' if SWAP & 0b1 else 'A'))


        '''
        USAGE
        -----
        No real documentation about Usage
        Nearly all is left... - did not seen implementation with 2 counters or 1 Usage
        '''

        if not Usage_A_DAT.isEmpty():
            print()
            print('USAGE_A')
            Describe_Usage(Usage_A_DAT, ContractMediumEndDate, Usage_A_CER)
            
        if not Usage_B_DAT.isEmpty():
            print()
            print('USAGE_B')
            Describe_Usage(Usage_B_DAT, ContractMediumEndDate, Usage_B_CER)


    return 0


if __name__ == '__main__':
    sys.exit(main())
