/*
 * Included before every file of squashfs-tools 4.6.1 that scripts/testdata.py
 * builds mksquashfs from (cc -include). mksquashfs keeps the major and minor
 * numbers of a device it makes from a pseudo file definition in a dev_t, with
 * makedev, and takes them out again with major and minor. Linux's dev_t holds
 * the 12-bit major and 20-bit minor numbers SquashFS stores; macOS's keeps
 * 8 bits of the major number only, so the device of major 4095 that
 * tools/squashfs-images/make.py asks for would come out as major 255. On
 * systems other than Linux these three are replaced by ones that keep 12 and
 * 20 bits in the 32 of a dev_t, so the images are the same there.
 */
#ifndef __linux__
#include <stdint.h>
#include <sys/types.h>
#undef major
#undef minor
#undef makedev
#define major(dev) ((unsigned int)(((uint32_t)(dev) >> 20) & 0xfff))
#define minor(dev) ((unsigned int)((uint32_t)(dev) & 0xfffff))
#define makedev(ma, mi) \
	((dev_t)((((uint32_t)(ma) & 0xfff) << 20) | ((uint32_t)(mi) & 0xfffff)))
#endif
