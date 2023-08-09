import sys
import binascii


def main(argv):
    argc = len(argv)
    if argc < 2:
        print('Usage:', argv[0], 'input.nfc output.eml')
        sys.exit(1)

    with open(argv[1], "r") as file_inp, open(argv[2], "wb") as file_out:
        for line in file_inp:
            print('line is ')
            print(line)
            if not line.startswith('Page '):
                continue
            starting_colon_index = line.index(':')
            start_index = starting_colon_index + 1
            myline = line[start_index:]
            myline = myline.replace(' ', '')
            file_out.write(bytes(myline, encoding='utf8'))


if __name__ == '__main__':
    main(sys.argv)
