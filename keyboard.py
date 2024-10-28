from keycodes import KEY_CODES

import subprocess
import sys

def run(path, src):
    # The `run` function receives the path to a pcap file and the USB address of the keyboard source.
    # It parses HID data and reconstructs the input text.
    
    # URB Function: URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER (0x0009)
    command = f'tshark -r {path} -Y "usb.src=={src}" -T fields -e usbhid.data'  
    result = subprocess.run(command, capture_output=True)
    data = result.stdout.decode("utf-8").split("\n")[:-1]

    Col = 0
    Ln = 0
    text = [[]]

    last = [0, 0, 0, 0, 0]
    current = [0, 0, 0, 0, 0]
    caps = 0

    for d in data:
        # Check if LEFTSHIFT or RIGHTSHIFT modifier is pressed
        shift = int(d[0:2] == "02" or d[0:2] == "20")

        last = current
        # Extract the contents of the keypress field
        current = [int(d[i : i + 2], base=16) for i in range(4, 14, 2)]

        for i in range(len(current)):
            if current[i] == 0:
                continue
            if current[i] == 1:
                print("ErrorRollOver")
            if current[i] == 2:
                print("ErrorPostFail")
            if current[i] == 3:
                print("ErrorUndefined")

            # Check if the keypress value was present in the previous packet
            # If so, this press was processed with the previous packet, so it is skipped here
            if current[i] in last:
                continue

            # Toggle CAPSLOCK on and off
            if KEY_CODES[current[i]][shift] == "[CAPSLOCK]":
                caps ^= 1
                continue

            # Change SHIFT modifier if keycode represents letter
            if current[i] >= 4 and current[i] <= 26:
                shift ^= caps

            if KEY_CODES[current[i]][shift] == "↑":
                if Ln > 0:
                    Ln -= 1
                    if Col > len(text[Ln]):
                        Col = len(text[Ln]) 
            elif KEY_CODES[current[i]][shift] == "↓":
                if Ln < len(text) - 1:
                    Ln += 1
                    if Col > len(text[Ln]):
                        Col = len(text[Ln])
            elif KEY_CODES[current[i]][shift] == "←":
                if Col > 0:
                    Col -= 1
                else:
                    if Ln > 0:
                        Ln -= 1
                        Col = len(text[Ln])
            elif KEY_CODES[current[i]][shift] == "→":
                if Col < len(text[Ln]):
                    Col += 1
                else:
                    if Ln < len(text) - 1:
                        Ln += 1
                        Col = 0
            elif KEY_CODES[current[i]][shift] == "\n":
                text.insert(Ln + 1, [])
                Ln += 1
                if Col < len(text[Ln - 1]) - 1:
                    text[Ln] = text[Ln - 1][Col:]
                    text[Ln - 1] = text[Ln - 1][:Col]
                Col = 0
            elif KEY_CODES[current[i]][shift] == "[BACKSPACE]":
                if Col > 0:
                    text[Ln].pop(Col - 1)
                    Col -= 1
                else:
                    if Ln > 0:
                        Col = len(text[Ln - 1])
                        text[Ln - 1] = text[Ln - 1] + text[Ln]
                        text.pop(Ln)
                        Ln -= 1
            else:
                text[Ln].insert(Col, KEY_CODES[current[i]][shift])
                Col += 1

    # Print the reconstructed message to standard output
    for t in text:
        print("".join(t))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python keyboard.py {path to .pcap file} {source address of the keyboard}")
        exit(-1)

    path = sys.argv[1]
    src = sys.argv[2]

    run(path=path, src=src)
