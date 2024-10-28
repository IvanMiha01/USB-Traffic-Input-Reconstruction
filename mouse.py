from PIL import Image, ImageDraw
import subprocess
import sys

width = 1920 * 2
height = 1080 * 2

image = Image.new("RGB", (width, height), "white")
draw = ImageDraw.Draw(image)

def drawLine(x1, y1, x2, y2):
    try:
        draw.line([(x1, y1), (x2, y2)], fill="black")
    except Exception as e:
        print(e, x1, y1, x2, y2)
        image.save("error.png")
        exit(-1)

def convertToOffset(s):
    # Function that converts an 8-bit signed number to an offset
    offset = int(s, base=16)
    if offset & 0x80:
        return offset - 0x100
    return offset


def run(path, src, filename):

    # URB Function: URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER (0x0009)
    command = f'tshark -r {path} -Y "usb.src=={src}" -T fields -e usbhid.data'
    result = subprocess.run(command, capture_output=True)
    data = result.stdout.decode("utf-8").split("\n")[:-1]

    clicked = False
    x = width // 2
    y = height // 2

    for d in data:
        # Check if the left mouse button is pressed
        if d[0:2] == "01":
            clicked = True
        else:
            clicked = False
            
        # Extracting the contents of the offset fields
        offsetX = convertToOffset(d[2:4])
        offsetY = convertToOffset(d[4:6])

        # Conditional line drawing
        if clicked:
            drawLine(x, y, x + offsetX, y + offsetY)

        x += offsetX
        y += offsetY
        if x < 0:
            x = 0
        if x > width:
            x = width
        if y < 0:
            y = 0
        if y > height:
            y = height

    image.save(filename + ".png")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("""Usage: python mouse.py {path to .pcap file} {source address of the mouse} {path to output file}""")
        exit(-1)

    path = sys.argv[1]
    src = sys.argv[2]
    filename = sys.argv[3]
    run(path=path, src=src, filename=filename)
