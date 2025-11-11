import struct
import os
from typing import Tuple, List


class LSBSteganography:
    def __init__(self):
        self.END_MARKER = "###END###"

    def string_to_binary(self, text: str) -> str:
        binary_str = ""
        for char in text:
            binary_char = bin(ord(char))[2:].zfill(8)
            binary_str += binary_char
        return binary_str

    def binary_to_string(self, binary_str: str) -> str:
        text = ""
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i + 8]
            if len(byte) == 8:
                text += chr(int(byte, 2))
        return text

    def get_pixel_sequence(self, width: int, height: int) -> List[Tuple[int, int]]:
        pixels = []
        center_x, center_y = width // 2, height // 2

        directions = [(1, 0), (0, 1), (-1, 0), (0, -1)]
        x, y = center_x, center_y
        step_size = 1
        step_count = 0
        direction = 0

        while len(pixels) < width * height:
            if 0 <= x < width and 0 <= y < height:
                pixels.append((x, y))

            dx, dy = directions[direction]
            x += dx
            y += dy
            step_count += 1

            if step_count == step_size:
                step_count = 0
                direction = (direction + 1) % 4
                if direction % 2 == 0:
                    step_size += 1

        return pixels[:width * height]

    def calculate_row_padding(self, width: int, bits_per_pixel: int) -> int:
        bytes_per_row = (width * bits_per_pixel) // 8
        padding = (4 - (bytes_per_row % 4)) % 4
        return padding

    def embed_message(self, input_image: str, output_image: str, message: str) -> bool:
        try:
            with open(input_image, 'rb') as f:
                file_header = f.read(14)

                info_header_size = struct.unpack('<I', f.read(4))[0]
                f.seek(14)
                info_header = f.read(info_header_size)

                bits_per_pixel = struct.unpack('<H', info_header[14:16])[0]
                if bits_per_pixel != 32:
                    print("Ошибка: Требуется 32-битное BMP изображение")
                    return False

                width = struct.unpack('<I', info_header[4:8])[0]
                height = struct.unpack('<I', info_header[8:12])[0]

                data_offset = struct.unpack('<I', file_header[10:14])[0]
                f.seek(data_offset)

                row_size = width * 4
                padding = self.calculate_row_padding(width, 32)
                image_data_size = (row_size + padding) * height

                image_data = bytearray(f.read(image_data_size))

            message_with_marker = message + self.END_MARKER
            binary_message = self.string_to_binary(message_with_marker)

            max_bits = width * height * 3
            if len(binary_message) > max_bits:
                print(f"Ошибка: Сообщение слишком длинное. Максимум: {max_bits // 8} символов")
                return False

            print(f"Длина сообщения в битах: {len(binary_message)}")
            print(f"Максимальная емкость: {max_bits} бит")
            print(f"Размер изображения: {width}x{height} пикселей")

            pixel_sequence = self.get_pixel_sequence(width, height)

            bit_index = 0
            for x, y in pixel_sequence:
                if bit_index >= len(binary_message):
                    break

                row = height - 1 - y
                pixel_pos = row * (width * 4 + padding) + x * 4

                for channel in range(3):  # 0=B, 1=G, 2=R, 3=A
                    if bit_index < len(binary_message):
                        current_byte = image_data[pixel_pos + channel]
                        message_bit = int(binary_message[bit_index])
                        new_byte = (current_byte & 0xFE) | message_bit
                        image_data[pixel_pos + channel] = new_byte
                        bit_index += 1

            with open(output_image, 'wb') as f:
                f.write(file_header)
                f.write(info_header)
                f.seek(data_offset)
                f.write(image_data)

            print(f"Сообщение успешно внедрено в {output_image}")
            print(f"Использовано {bit_index} бит из {max_bits} доступных")
            print(f"Использовано каналов: B, G, R (Alpha канал не используется)")
            return True

        except Exception as e:
            print(f"Ошибка при внедрении: {e}")
            return False

    def extract_message(self, image_path: str) -> str:
        try:
            with open(image_path, 'rb') as f:

                file_header = f.read(14)
                info_header_size = struct.unpack('<I', f.read(4))[0]
                f.seek(14)
                info_header = f.read(info_header_size)

                bits_per_pixel = struct.unpack('<H', info_header[14:16])[0]
                if bits_per_pixel != 32:
                    print("Ошибка: Файл не является 32-битным BMP")
                    return ""

                width = struct.unpack('<I', info_header[4:8])[0]
                height = struct.unpack('<I', info_header[8:12])[0]
                data_offset = struct.unpack('<I', file_header[10:14])[0]

                f.seek(data_offset)

                padding = self.calculate_row_padding(width, 32)
                row_size = width * 4 + padding

                image_data = f.read(row_size * height)

            binary_message = ""
            end_marker_binary = self.string_to_binary(self.END_MARKER)

            pixel_sequence = self.get_pixel_sequence(width, height)

            for x, y in pixel_sequence:
                if len(binary_message) >= len(end_marker_binary):
                    if binary_message[-len(end_marker_binary):] == end_marker_binary:
                        break

                row = height - 1 - y
                pixel_pos = row * (width * 4 + padding) + x * 4

                for channel in range(3):
                    if pixel_pos + channel < len(image_data):
                        lsb = image_data[pixel_pos + channel] & 1
                        binary_message += str(lsb)

                        if len(binary_message) >= len(end_marker_binary):
                            if binary_message[-len(end_marker_binary):] == end_marker_binary:
                                break

            if binary_message.endswith(end_marker_binary):
                binary_message = binary_message[:-len(end_marker_binary)]

            message = self.binary_to_string(binary_message)
            return message

        except Exception as e:
            print(f"Ошибка при извлечении: {e}")
            return ""


def main():
    stego = LSBSteganography()

    print("1. Внедрить сообщение")
    print("2. Извлечь сообщение")

    choice = input()

    messages = ["Uryadova Nataliya Ivanovna", "Peter Piper picked a peck of pickled peppers; A peck of pickled peppers Peter Piper picked.", "i love infobez"]

    if choice == "1":
        for msg in messages:
            input_file = "image.bmp"
            output_file = f"result_{messages.index(msg)}.bmp"
            # message = "Uryadova Nataliya Ivanovna"

            if not os.path.exists(input_file):
                print("Ошибка: Файл не найден")

            stego.embed_message(input_file, output_file, msg)

    elif choice == "2":
        lngth = len(messages)
        for i in range(lngth):
            image_file = f"result_{i}.bmp"

            if not os.path.exists(image_file):
                print("Ошибка: Файл не найден")

            extracted_message = stego.extract_message(image_file)
            print(f"Извлеченное сообщение: {extracted_message}")


if __name__ == "__main__":
    main()
