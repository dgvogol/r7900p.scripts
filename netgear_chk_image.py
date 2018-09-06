#! /usr/bin/env python3

from construct import Struct, Bytes, Int32ub, Int32ul, CString
import os, sys
import typing
import argparse
import logging
from io import StringIO

CHUNK_SIZE = 64 * 1024

CHK_MAGIC = 0x2a23245e
CHK_HEADER = Struct(
    'magic' / Int32ub,
    'header_len' / Int32ub,
    'reserved' / Bytes(8),
    'kernel_chksum' / Int32ub,
    'rootfs_chksum' / Int32ub,
    'kernel_len' / Int32ub,
    'rootfs_len' / Int32ub,
    'image_chksum' / Int32ub,
    'header_chksum' / Int32ub
)

BCM_BCMFS_TAG = b"BcmFs-"
BCM_BCMFS_TYPE_UBIFS = b"ubifs"
BCM_BCMFS_TYPE_JFFS2 = b"jffs2"
BCM_BCMFS_TYPE_SQUBIFS = b"ubifs_sq"

# typedef struct _WFI_TAG
# {
#     unsigned int wfiCrc;
#     unsigned int wfiVersion;
#     unsigned int wfiChipId;
#     unsigned int wfiFlashType;
#     unsigned int wfiFlags;
# } WFI_TAG, *PWFI_TAG;

WFI_TOKEN = Struct(
    'crc' / Int32ul,
    'version' / Int32ul,
    'chip_id' / Int32ul,
    'flash_type' / Int32ul,
    'flags' / Int32ul
)

WFI_VERSION = 0x00005732
WFI_ANY_VERS_MASK = 0x0000ff00
WFI_ANY_VERS = 0x00005700
WFI_VERSION_NAND_1MB_DATA = 0x00005731
WFI_NOR_FLASH = 1
WFI_NAND16_FLASH = 2
WFI_NAND128_FLASH = 3
WFI_NAND256_FLASH = 4
WFI_NAND512_FLASH = 5
WFI_NAND1024_FLASH = 6
WFI_NAND2048_FLASH = 7
WFI_NANDTYPE_FLASH_MIN = WFI_NAND16_FLASH
WFI_NANDTYPE_FLASH_MAX = WFI_NAND2048_FLASH

WFI_FLAG_HAS_PMC = 0x1
WFI_FLAG_SUPPORTS_BTRM = 0x2

WFI_CRC32_INIT = 0xffffffff
WFI_CRC32_TABLE = [
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
]


def wfi_crc32_update(data, crc):
    global WFI_CRC32_TABLE
    for byte in data:
        crc = ((crc >> 8) & 0xffffffff) ^ WFI_CRC32_TABLE[(crc ^ byte) & 0xff]
    return crc


class NetgearChecksum(object):
    def __init__(self):
        self._c0 = 0
        self._c1 = 0

    def add(self, data):
        for octet in data:
            self._c0 = (self._c0 + (octet & 0xff)) & 0xffffffff
            self._c1 = (self._c1 + self._c0) & 0xffffffff

    def result(self):
        b = (self._c0 & 0xffff) + ((self._c0 >> 16) & 0xffff)
        self._c0 = ((b >> 16) + b) & 0xffff
        b = (self._c1 & 0xffff) + ((self._c1 >> 16) & 0xffff)
        self._c1 = ((b >> 16) + b) & 0xffff
        return ((self._c1 << 16) | self._c0) & 0xffffffff

    def reset(self):
        self._c0 = 0
        self._c1 = 0


def netgear_image_verify(firmware):
    if not os.path.isfile(firmware):
        return False
    stat = os.stat(firmware)
    file_size = stat.st_size
    if file_size < CHK_HEADER.sizeof():
        return False

    with open(firmware, 'rb') as fp:
        header, board_id = netgear_image_load_header(fp)
        if header is None:
            return False

        checksum = NetgearChecksum()
        image_checksum = NetgearChecksum()

        fp.seek(header.header_len)
        # verify kernel
        if header.kernel_len > 0:
            remaining = header.kernel_len
            while remaining > 0:
                if remaining > CHUNK_SIZE:
                    nbytes = CHUNK_SIZE
                else:
                    nbytes = remaining
                data = fp.read(nbytes)
                if len(data) != nbytes:
                    return False
                checksum.add(data)
                image_checksum.add(data)

                remaining -= nbytes

            if header.kernel_chksum != checksum.result():
                return False

        # verify rootfs
        checksum.reset()
        if header.rootfs_len > 0:
            remaining = header.rootfs_len
            while remaining > 0:
                if remaining > CHUNK_SIZE:
                    nbytes = CHUNK_SIZE
                else:
                    nbytes = remaining
                data = fp.read(nbytes)
                if len(data) != nbytes:
                    return False
                checksum.add(data)
                image_checksum.add(data)

                remaining -= nbytes

            if header.rootfs_chksum != checksum.result():
                return False

        if image_checksum.result() != header.image_chksum:
            return False

    return True


def netgear_image_load_header(fp: typing.IO):
    fp.seek(0, 2)
    file_size = fp.tell()
    if file_size < CHK_HEADER.sizeof():
        return None, None

    fp.seek(0)
    header = CHK_HEADER.parse(fp.read(CHK_HEADER.sizeof()))
    if header.magic != CHK_MAGIC:
        return None, None
    if file_size < header.header_len:
        return None, None
    board_id = fp.read(header.header_len - CHK_HEADER.sizeof())
    # verify header checksum
    checksum = NetgearChecksum()
    header_cksum = header.header_chksum
    header.header_chksum = 0
    checksum.add(CHK_HEADER.build(header))
    checksum.add(board_id)
    if checksum.result() != header_cksum:
        return None, None
    return header, board_id


INDENTION = ' '


class LogWithIndent(logging.Formatter):
    def format(self, record):
        s = super().format(record)
        lines = s.splitlines(keepends=True)
        buffer = StringIO()
        idx = 0
        for ln in lines:
            if idx == 0:
                buffer.write(ln)
            else:
                buffer.write(INDENTION + ln)
            idx += 1
        return buffer.getvalue()


def init_logging(verbose):
    formatter = LogWithIndent(fmt='[%(name)s - %(levelname)s]\n%(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logging.basicConfig(level=verbose, handlers=[handler])


def extract_kernel_image(chk_image, kernel_image=None):
    logger = logging.getLogger('EXTRACT')
    with open(chk_image, 'rb') as fp:
        header, board_id = netgear_image_load_header(fp)
        if header.kernel_len <= 0:
            logger.info('no kernel image in <%s>', chk_image)
            return

        fp.seek(header.header_len)
        remaining_bytes = header.kernel_len

        if kernel_image is None:
            data = fp.read(remaining_bytes)
            if len(data) < remaining_bytes:
                logger.warning('kernel image size mismatch, expected size = %d, actual size = %d',
                               remaining_bytes, len(data))
            return data
        else:
            with open(kernel_image, 'wb') as outfp:
                while remaining_bytes > 0:
                    if remaining_bytes > CHUNK_SIZE:
                        nbytes = CHUNK_SIZE
                    else:
                        nbytes = remaining_bytes
                    data = fp.read(nbytes)
                    if len(data) <= 0:
                        break

                    outfp.write(data)
                    remaining_bytes -= len(data)

                if remaining_bytes > 0:
                    logger.warning('kernel image size mismatch, remaining bytes = %d',
                                   remaining_bytes)

            logger.info('kernel image saved to <%s>, total bytes: %d',
                        kernel_image, header.kernel_len)

            return kernel_image


def extract_rootfs_image(chk_image, rootfs_image=None):
    logger = logging.getLogger('EXTRACT')
    with open(chk_image, 'rb') as fp:
        header, board_id = netgear_image_load_header(fp)
        if header.rootfs_len <= 0:
            logger.info('no rootfs image in <%s>', chk_image)
            return

        fp.seek(header.header_len + header.kernel_len)
        remaining_bytes = header.rootfs_len

        if rootfs_image is None:
            data = fp.read(remaining_bytes)
            if len(data) < remaining_bytes:
                logger.warning('rootfs image size mismatch, expected size = %d, actual size = %d',
                               remaining_bytes, len(data))
            return data
        else:
            with open(rootfs_image, 'wb') as outfp:
                while remaining_bytes > 0:
                    if remaining_bytes > CHUNK_SIZE:
                        nbytes = CHUNK_SIZE
                    else:
                        nbytes = remaining_bytes
                    data = fp.read(nbytes)
                    if len(data) <= 0:
                        break

                    outfp.write(data)
                    remaining_bytes -= len(data)

                if remaining_bytes > 0:
                    logger.warning('rootfs image size mismatch, remaining bytes = %d',
                                   remaining_bytes)

            logger.info('rootfs image saved to <%s>, total bytes: %d',
                        rootfs_image, header.rootfs_len)

            return rootfs_image


def brcm_image_check(data):
    token_size = WFI_TOKEN.sizeof()
    assert (len(data) >= token_size)
    token = WFI_TOKEN.parse(data[-token_size:])
    crc = wfi_crc32_update(data[:-token_size], 0xffffffff)
    if crc == token.crc:
        return data[:-token_size], token
    return None, None


def brcm_extract_rootfs_image(image_data, token):
    logger = logging.getLogger('BRCM')
    if token.flash_type != WFI_NAND128_FLASH:
        logger.warning('flash type not supported')
        return None, None
    block_size = 128 * 1024
    pos = block_size

    while pos < len(image_data):
        # search in last 256 bytes in each block for "BcmFs-" tag
        if image_data[pos - 256:pos - 250] == b'BcmFs-':
            break
        pos += block_size

    if pos >= len(image_data):
        logger.error('rootfs not found')

    fstype = CString().parse(image_data[pos - 256:pos]).replace(b'BcmFs-', b'')

    return image_data[pos:], fstype


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action', default=None)
    parser.add_argument('-w', '--firmware', default=None)
    parser.add_argument('-v', '--verbose', action='store_true', default=False)
    parser.add_argument('-o', '--output', default=None)

    options, args = parser.parse_known_args(sys.argv)

    # set up message logging
    if options.verbose:
        verbose_flags = logging.DEBUG
    else:
        verbose_flags = logging.INFO
    init_logging(verbose_flags)

    logger = logging.getLogger('MAIN')

    # check command line
    if options.action in set(['check', 'info', 'extract_rootfs', 'extract_kernel', 'extract_rootfs_2']):
        if not options.firmware and len(args) < 2:
            logger.error('please specify the firmware file')
            sys.exit(-1)

        if options.firmware:
            firmware = options.firmware
        else:
            firmware = args[1]

        if not os.path.isfile(firmware):
            logger.error('firmware file <%s> does not exist', firmware)
            sys.exit(-1)
    else:
        firmware = None

    # chk image sanity check
    if options.action == 'check':
        logger.info('verifying firmware file: <%s> ...', firmware)
        if netgear_image_verify(firmware):
            logger.info('firmware file <%s> is GOOD', firmware)
        else:
            logger.info('firmware file <%s> is CORRUPTED', firmware)
        sys.exit(0)

    elif options.action == 'info':
        with open(firmware, 'rb') as fp:
            header, board_id = netgear_image_load_header(fp)
            if header.rootfs_len > 0:
                logger.info('rootfs image length: %d', header.rootfs_len)
            else:
                logger.info("no rootfs image")
            if header.kernel_len > 0:
                logger.info('kernel image length: %d', header.kernel_len)
            else:
                logger.info('no kernel image')

    elif options.action == 'extract_rootfs':
        if not options.output:
            logger.warning('please specify output filename for rootfs image')
            sys.exit(-1)

        result = extract_rootfs_image(firmware, options.output)
        if not result:
            sys.exit(-1)

    elif options.action == 'extract_kernel':
        if not options.output:
            logger.warning('please specify output filename for kernel image')
            sys.exit(-1)

        result = extract_kernel_image(firmware, options.output)
        if not result:
            sys.exit(-1)

    elif options.action == 'extract_rootfs_2':
        if not firmware:
            logger.warning("no input file")
            sys.exit(-1)

        data = extract_kernel_image(firmware)
        image_data, token = brcm_image_check(data)
        rootfs_data, fstype = brcm_extract_rootfs_image(image_data, token)

        if rootfs_data:
            pass
        else:
            logger.error('no rootfs found in image')

        if not options.output:
            logger.warning('no output rootfs file name specified')
            sys.exit(-1)

        with open(options.output, 'wb') as outfp:
            outfp.write(rootfs_data)

        logger.info('rootfs saved to image: <%s>, fs_type: <%s>, image_size: <%d>',
                    options.output, fstype.decode(), len(rootfs_data))


if __name__ == '__main__':
    main()
