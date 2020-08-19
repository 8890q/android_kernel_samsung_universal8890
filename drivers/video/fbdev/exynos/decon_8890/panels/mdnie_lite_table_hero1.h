#ifndef __MDNIE_TABLE_HERO1_H__
#define __MDNIE_TABLE_HERO1_H__

/* 2016.10.13 */

/* SCR Position can be different each panel */
static struct mdnie_scr_info scr_info = {
	.index = 1,
	.cr = 34,		/* ASCR_WIDE_CR[7:0] */
	.wr = 52,		/* ASCR_WIDE_WR[7:0] */
	.wg = 54,		/* ASCR_WIDE_WG[7:0] */
	.wb = 56		/* ASCR_WIDE_WB[7:0] */
};

static struct mdnie_trans_info trans_info = {
	.index = 1,
	.offset = 2,
	.enable = 1
};

static struct mdnie_night_info night_info = {
	.max_w = 24,
	.max_h = 11
};

static struct mdnie_color_lens_info color_lens_info = {
	.max_color = 12,
	.max_level = 9,
	.max_w = 24
};

static inline int color_offset_f1(int x, int y)
{
	return ((y << 10) - (((x << 10) * 43) / 40) + (45 << 10)) >> 10;
}
static inline int color_offset_f2(int x, int y)
{
	return ((y << 10) - (((x << 10) * 310) / 297) - (3 << 10)) >> 10;
}
static inline int color_offset_f3(int x, int y)
{
	return ((y << 10) + (((x << 10) * 367) / 84) - (16305 << 10)) >> 10;
}
static inline int color_offset_f4(int x, int y)
{
	return ((y << 10) + (((x << 10) * 333) / 107) - (12396 << 10)) >> 10;
}

/* color coordination order is WR, WG, WB */
static unsigned char coordinate_data_1[] = {
	0xff, 0xff, 0xff, /* dummy */
	0xff, 0xfb, 0xfb, /* Tune_1 */
	0xff, 0xfd, 0xff, /* Tune_2 */
	0xfb, 0xfa, 0xff, /* Tune_3 */
	0xff, 0xfe, 0xfc, /* Tune_4 */
	0xff, 0xff, 0xff, /* Tune_5 */
	0xfb, 0xfc, 0xff, /* Tune_6 */
	0xfd, 0xff, 0xfa, /* Tune_7 */
	0xfd, 0xff, 0xfd, /* Tune_8 */
	0xfb, 0xff, 0xff, /* Tune_9 */
};

static unsigned char coordinate_data_2[] = {
	0xff, 0xff, 0xff, /* dummy */
	0xff, 0xf7, 0xee, /* Tune_1 */
	0xff, 0xf8, 0xf1, /* Tune_2 */
	0xff, 0xf9, 0xf5, /* Tune_3 */
	0xff, 0xf9, 0xee, /* Tune_4 */
	0xff, 0xfa, 0xf1, /* Tune_5 */
	0xff, 0xfb, 0xf5, /* Tune_6 */
	0xff, 0xfc, 0xee, /* Tune_7 */
	0xff, 0xfc, 0xf1, /* Tune_8 */
	0xff, 0xfd, 0xf4, /* Tune_9 */
};

static unsigned char *coordinate_data[MODE_MAX] = {
	coordinate_data_1,
	coordinate_data_2,
	coordinate_data_2,
	coordinate_data_1,
	coordinate_data_1,
};

static unsigned char adjust_ldu_data_1[] = {
	0xff, 0xff, 0xff,
	0xf6, 0xfa, 0xff,
	0xf4, 0xf8, 0xff,
	0xe9, 0xf2, 0xff,
	0xe2, 0xef, 0xff,
	0xd4, 0xe8, 0xff,
};

static unsigned char adjust_ldu_data_2[] = {
	0xff, 0xfa, 0xf1,
	0xff, 0xfd, 0xf8,
	0xff, 0xfd, 0xfa,
	0xfa, 0xfd, 0xff,
	0xf5, 0xfb, 0xff,
	0xe5, 0xf3, 0xff,
};

static unsigned char *adjust_ldu_data[MODE_MAX] = {
	adjust_ldu_data_1,
	adjust_ldu_data_2,
	adjust_ldu_data_2,
	adjust_ldu_data_1,
	adjust_ldu_data_1,
};

static unsigned char night_mode_data[] = {
	0x00, 0xff, 0xfa, 0x00, 0xf1, 0x00, 0xff, 0x00, 0x00, 0xfa, 0xf1, 0x00, 0xff, 0x00, 0xfa, 0x00, 0x00, 0xf1, 0xff, 0x00, 0xfa, 0x00, 0xf1, 0x00, /* 6500K */
	0x00, 0xff, 0xf8, 0x00, 0xeb, 0x00, 0xff, 0x00, 0x00, 0xf8, 0xeb, 0x00, 0xff, 0x00, 0xf8, 0x00, 0x00, 0xeb, 0xff, 0x00, 0xf8, 0x00, 0xeb, 0x00, /* 6100K */
	0x00, 0xff, 0xf5, 0x00, 0xe2, 0x00, 0xff, 0x00, 0x00, 0xf5, 0xe2, 0x00, 0xff, 0x00, 0xf5, 0x00, 0x00, 0xe2, 0xff, 0x00, 0xf5, 0x00, 0xe2, 0x00, /* 5700K */
	0x00, 0xff, 0xf2, 0x00, 0xda, 0x00, 0xff, 0x00, 0x00, 0xf2, 0xda, 0x00, 0xff, 0x00, 0xf2, 0x00, 0x00, 0xda, 0xff, 0x00, 0xf2, 0x00, 0xda, 0x00, /* 5300K */
	0x00, 0xff, 0xee, 0x00, 0xd0, 0x00, 0xff, 0x00, 0x00, 0xee, 0xd0, 0x00, 0xff, 0x00, 0xee, 0x00, 0x00, 0xd0, 0xff, 0x00, 0xee, 0x00, 0xd0, 0x00, /* 4900K */
	0x00, 0xff, 0xe9, 0x00, 0xc4, 0x00, 0xff, 0x00, 0x00, 0xe9, 0xc4, 0x00, 0xff, 0x00, 0xe9, 0x00, 0x00, 0xc4, 0xff, 0x00, 0xe9, 0x00, 0xc4, 0x00, /* 4500K */
	0x00, 0xff, 0xe3, 0x00, 0xb4, 0x00, 0xff, 0x00, 0x00, 0xe3, 0xb4, 0x00, 0xff, 0x00, 0xe3, 0x00, 0x00, 0xb4, 0xff, 0x00, 0xe3, 0x00, 0xb4, 0x00, /* 4100K */
	0x00, 0xff, 0xdd, 0x00, 0xa4, 0x00, 0xff, 0x00, 0x00, 0xdd, 0xa4, 0x00, 0xff, 0x00, 0xdd, 0x00, 0x00, 0xa4, 0xff, 0x00, 0xdd, 0x00, 0xa4, 0x00, /* 3700K */
	0x00, 0xff, 0xd6, 0x00, 0x91, 0x00, 0xff, 0x00, 0x00, 0xd6, 0x91, 0x00, 0xff, 0x00, 0xd6, 0x00, 0x00, 0x91, 0xff, 0x00, 0xd6, 0x00, 0x91, 0x00, /* 3300K */
	0x00, 0xff, 0xcb, 0x00, 0x7b, 0x00, 0xff, 0x00, 0x00, 0xcb, 0x7b, 0x00, 0xff, 0x00, 0xcb, 0x00, 0x00, 0x7b, 0xff, 0x00, 0xcb, 0x00, 0x7b, 0x00, /* 2900K */
	0x00, 0xff, 0xbe, 0x00, 0x68, 0x00, 0xff, 0x00, 0x00, 0xbe, 0x68, 0x00, 0xff, 0x00, 0xbe, 0x00, 0x00, 0x68, 0xff, 0x00, 0xbe, 0x00, 0x68, 0x00  /* 2500K */
};

static unsigned char color_lens_data[] = {
	//Blue
	0x00, 0xcc, 0xcc, 0x00, 0xff, 0x33, 0xcc, 0x00, 0x00, 0xcc, 0xff, 0x33, 0xcc, 0x00, 0xcc, 0x00, 0x33, 0xff, 0xcc, 0x00, 0xcc, 0x00, 0xff, 0x33, /* 20% */
	0x00, 0xbf, 0xbf, 0x00, 0xff, 0x40, 0xbf, 0x00, 0x00, 0xbf, 0xff, 0x40, 0xbf, 0x00, 0xbf, 0x00, 0x40, 0xff, 0xbf, 0x00, 0xbf, 0x00, 0xff, 0x40, /* 25% */
	0x00, 0xb2, 0xb2, 0x00, 0xff, 0x4d, 0xb2, 0x00, 0x00, 0xb2, 0xff, 0x4d, 0xb2, 0x00, 0xb2, 0x00, 0x4d, 0xff, 0xb2, 0x00, 0xb2, 0x00, 0xff, 0x4d, /* 30% */
	0x00, 0xa6, 0xa6, 0x00, 0xff, 0x59, 0xa6, 0x00, 0x00, 0xa6, 0xff, 0x59, 0xa6, 0x00, 0xa6, 0x00, 0x59, 0xff, 0xa6, 0x00, 0xa6, 0x00, 0xff, 0x59, /* 35% */
	0x00, 0x99, 0x99, 0x00, 0xff, 0x66, 0x99, 0x00, 0x00, 0x99, 0xff, 0x66, 0x99, 0x00, 0x99, 0x00, 0x66, 0xff, 0x99, 0x00, 0x99, 0x00, 0xff, 0x66, /* 40% */
	0x00, 0x8c, 0x8c, 0x00, 0xff, 0x73, 0x8c, 0x00, 0x00, 0x8c, 0xff, 0x73, 0x8c, 0x00, 0x8c, 0x00, 0x73, 0xff, 0x8c, 0x00, 0x8c, 0x00, 0xff, 0x73, /* 45% */
	0x00, 0x7f, 0x7f, 0x00, 0xff, 0x80, 0x7f, 0x00, 0x00, 0x7f, 0xff, 0x80, 0x7f, 0x00, 0x7f, 0x00, 0x80, 0xff, 0x7f, 0x00, 0x7f, 0x00, 0xff, 0x80, /* 50% */
	0x00, 0x73, 0x73, 0x00, 0xff, 0x8c, 0x73, 0x00, 0x00, 0x73, 0xff, 0x8c, 0x73, 0x00, 0x73, 0x00, 0x8c, 0xff, 0x73, 0x00, 0x73, 0x00, 0xff, 0x8c, /* 55% */
	0x00, 0x66, 0x66, 0x00, 0xff, 0x99, 0x66, 0x00, 0x00, 0x66, 0xff, 0x99, 0x66, 0x00, 0x66, 0x00, 0x99, 0xff, 0x66, 0x00, 0x66, 0x00, 0xff, 0x99, /* 60% */

	//Azure
	0x00, 0xcc, 0xe5, 0x19, 0xff, 0x33, 0xcc, 0x00, 0x19, 0xe5, 0xff, 0x33, 0xcc, 0x00, 0xe5, 0x19, 0x33, 0xff, 0xcc, 0x00, 0xe5, 0x19, 0xff, 0x33, /* 20% */
	0x00, 0xbf, 0xdf, 0x20, 0xff, 0x40, 0xbf, 0x00, 0x20, 0xdf, 0xff, 0x40, 0xbf, 0x00, 0xdf, 0x20, 0x40, 0xff, 0xbf, 0x00, 0xdf, 0x20, 0xff, 0x40, /* 25% */
	0x00, 0xb2, 0xd8, 0x26, 0xff, 0x4d, 0xb2, 0x00, 0x26, 0xd8, 0xff, 0x4d, 0xb2, 0x00, 0xd8, 0x26, 0x4d, 0xff, 0xb2, 0x00, 0xd8, 0x26, 0xff, 0x4d, /* 30% */
	0x00, 0xa6, 0xd2, 0x2c, 0xff, 0x59, 0xa6, 0x00, 0x2c, 0xd2, 0xff, 0x59, 0xa6, 0x00, 0xd2, 0x2c, 0x59, 0xff, 0xa6, 0x00, 0xd2, 0x2c, 0xff, 0x59, /* 35% */
	0x00, 0x99, 0xcc, 0x33, 0xff, 0x66, 0x99, 0x00, 0x33, 0xcc, 0xff, 0x66, 0x99, 0x00, 0xcc, 0x33, 0x66, 0xff, 0x99, 0x00, 0xcc, 0x33, 0xff, 0x66, /* 40% */
	0x00, 0x8c, 0xc5, 0x39, 0xff, 0x73, 0x8c, 0x00, 0x39, 0xc5, 0xff, 0x73, 0x8c, 0x00, 0xc5, 0x39, 0x73, 0xff, 0x8c, 0x00, 0xc5, 0x39, 0xff, 0x73, /* 45% */
	0x00, 0x7f, 0xbf, 0x40, 0xff, 0x80, 0x7f, 0x00, 0x40, 0xbf, 0xff, 0x80, 0x7f, 0x00, 0xbf, 0x40, 0x80, 0xff, 0x7f, 0x00, 0xbf, 0x40, 0xff, 0x80, /* 50% */
	0x00, 0x73, 0xb9, 0x46, 0xff, 0x8c, 0x73, 0x00, 0x46, 0xb9, 0xff, 0x8c, 0x73, 0x00, 0xb9, 0x46, 0x8c, 0xff, 0x73, 0x00, 0xb9, 0x46, 0xff, 0x8c, /* 55% */
	0x00, 0x66, 0xb2, 0x4c, 0xff, 0x99, 0x66, 0x00, 0x4c, 0xb2, 0xff, 0x99, 0x66, 0x00, 0xb2, 0x4c, 0x99, 0xff, 0x66, 0x00, 0xb2, 0x4c, 0xff, 0x99, /* 60% */

	//Cyan
	0x00, 0xcc, 0xff, 0x33, 0xff, 0x33, 0xcc, 0x00, 0x33, 0xff, 0xff, 0x33, 0xcc, 0x00, 0xff, 0x33, 0x33, 0xff, 0xcc, 0x00, 0xff, 0x33, 0xff, 0x33, /* 20% */
	0x00, 0xbf, 0xff, 0x40, 0xff, 0x40, 0xbf, 0x00, 0x40, 0xff, 0xff, 0x40, 0xbf, 0x00, 0xff, 0x40, 0x40, 0xff, 0xbf, 0x00, 0xff, 0x40, 0xff, 0x40, /* 25% */
	0x00, 0xb2, 0xff, 0x4d, 0xff, 0x4d, 0xb2, 0x00, 0x4d, 0xff, 0xff, 0x4d, 0xb2, 0x00, 0xff, 0x4d, 0x4d, 0xff, 0xb2, 0x00, 0xff, 0x4d, 0xff, 0x4d, /* 30% */
	0x00, 0xa6, 0xff, 0x59, 0xff, 0x59, 0xa6, 0x00, 0x59, 0xff, 0xff, 0x59, 0xa6, 0x00, 0xff, 0x59, 0x59, 0xff, 0xa6, 0x00, 0xff, 0x59, 0xff, 0x59, /* 35% */
	0x00, 0x99, 0xff, 0x66, 0xff, 0x66, 0x99, 0x00, 0x66, 0xff, 0xff, 0x66, 0x99, 0x00, 0xff, 0x66, 0x66, 0xff, 0x99, 0x00, 0xff, 0x66, 0xff, 0x66, /* 40% */
	0x00, 0x8c, 0xff, 0x73, 0xff, 0x73, 0x8c, 0x00, 0x73, 0xff, 0xff, 0x73, 0x8c, 0x00, 0xff, 0x73, 0x73, 0xff, 0x8c, 0x00, 0xff, 0x73, 0xff, 0x73, /* 45% */
	0x00, 0x7f, 0xff, 0x80, 0xff, 0x80, 0x7f, 0x00, 0x80, 0xff, 0xff, 0x80, 0x7f, 0x00, 0xff, 0x80, 0x80, 0xff, 0x7f, 0x00, 0xff, 0x80, 0xff, 0x80, /* 50% */
	0x00, 0x73, 0xff, 0x8c, 0xff, 0x8c, 0x73, 0x00, 0x8c, 0xff, 0xff, 0x8c, 0x73, 0x00, 0xff, 0x8c, 0x8c, 0xff, 0x73, 0x00, 0xff, 0x8c, 0xff, 0x8c, /* 55% */
	0x00, 0x66, 0xff, 0x99, 0xff, 0x99, 0x66, 0x00, 0x99, 0xff, 0xff, 0x99, 0x66, 0x00, 0xff, 0x99, 0x99, 0xff, 0x66, 0x00, 0xff, 0x99, 0xff, 0x99, /* 60% */

	//Spring green
	0x00, 0xcc, 0xff, 0x33, 0xe5, 0x19, 0xcc, 0x00, 0x33, 0xff, 0xe5, 0x19, 0xcc, 0x00, 0xff, 0x33, 0x19, 0xe5, 0xcc, 0x00, 0xff, 0x33, 0xe5, 0x19, /* 20% */
	0x00, 0xbf, 0xff, 0x40, 0xdf, 0x20, 0xbf, 0x00, 0x40, 0xff, 0xdf, 0x20, 0xbf, 0x00, 0xff, 0x40, 0x20, 0xdf, 0xbf, 0x00, 0xff, 0x40, 0xdf, 0x20, /* 25% */
	0x00, 0xb2, 0xff, 0x4d, 0xd8, 0x26, 0xb2, 0x00, 0x4d, 0xff, 0xd8, 0x26, 0xb2, 0x00, 0xff, 0x4d, 0x26, 0xd8, 0xb2, 0x00, 0xff, 0x4d, 0xd8, 0x26, /* 30% */
	0x00, 0xa6, 0xff, 0x59, 0xd2, 0x2c, 0xa6, 0x00, 0x59, 0xff, 0xd2, 0x2c, 0xa6, 0x00, 0xff, 0x59, 0x2c, 0xd2, 0xa6, 0x00, 0xff, 0x59, 0xd2, 0x2c, /* 35% */
	0x00, 0x99, 0xff, 0x66, 0xcc, 0x33, 0x99, 0x00, 0x66, 0xff, 0xcc, 0x33, 0x99, 0x00, 0xff, 0x66, 0x33, 0xcc, 0x99, 0x00, 0xff, 0x66, 0xcc, 0x33, /* 40% */
	0x00, 0x8c, 0xff, 0x73, 0xc5, 0x39, 0x8c, 0x00, 0x73, 0xff, 0xc5, 0x39, 0x8c, 0x00, 0xff, 0x73, 0x39, 0xc5, 0x8c, 0x00, 0xff, 0x73, 0xc5, 0x39, /* 45% */
	0x00, 0x7f, 0xff, 0x80, 0xbf, 0x40, 0x7f, 0x00, 0x80, 0xff, 0xbf, 0x40, 0x7f, 0x00, 0xff, 0x80, 0x40, 0xbf, 0x7f, 0x00, 0xff, 0x80, 0xbf, 0x40, /* 50% */
	0x00, 0x73, 0xff, 0x8c, 0xb9, 0x46, 0x73, 0x00, 0x8c, 0xff, 0xb9, 0x46, 0x73, 0x00, 0xff, 0x8c, 0x46, 0xb9, 0x73, 0x00, 0xff, 0x8c, 0xb9, 0x46, /* 55% */
	0x00, 0x66, 0xff, 0x99, 0xb2, 0x4c, 0x66, 0x00, 0x99, 0xff, 0xb2, 0x4c, 0x66, 0x00, 0xff, 0x99, 0x4c, 0xb2, 0x66, 0x00, 0xff, 0x99, 0xb2, 0x4c, /* 60% */

	//Green
	0x00, 0xcc, 0xff, 0x33, 0xcc, 0x00, 0xcc, 0x00, 0x33, 0xff, 0xcc, 0x00, 0xcc, 0x00, 0xff, 0x33, 0x00, 0xcc, 0xcc, 0x00, 0xff, 0x33, 0xcc, 0x00, /* 20% */
	0x00, 0xbf, 0xff, 0x40, 0xbf, 0x00, 0xbf, 0x00, 0x40, 0xff, 0xbf, 0x00, 0xbf, 0x00, 0xff, 0x40, 0x00, 0xbf, 0xbf, 0x00, 0xff, 0x40, 0xbf, 0x00, /* 25% */
	0x00, 0xb2, 0xff, 0x4d, 0xb2, 0x00, 0xb2, 0x00, 0x4d, 0xff, 0xb2, 0x00, 0xb2, 0x00, 0xff, 0x4d, 0x00, 0xb2, 0xb2, 0x00, 0xff, 0x4d, 0xb2, 0x00, /* 30% */
	0x00, 0xa6, 0xff, 0x59, 0xa6, 0x00, 0xa6, 0x00, 0x59, 0xff, 0xa6, 0x00, 0xa6, 0x00, 0xff, 0x59, 0x00, 0xa6, 0xa6, 0x00, 0xff, 0x59, 0xa6, 0x00, /* 35% */
	0x00, 0x99, 0xff, 0x66, 0x99, 0x00, 0x99, 0x00, 0x66, 0xff, 0x99, 0x00, 0x99, 0x00, 0xff, 0x66, 0x00, 0x99, 0x99, 0x00, 0xff, 0x66, 0x99, 0x00, /* 40% */
	0x00, 0x8c, 0xff, 0x73, 0x8c, 0x00, 0x8c, 0x00, 0x73, 0xff, 0x8c, 0x00, 0x8c, 0x00, 0xff, 0x73, 0x00, 0x8c, 0x8c, 0x00, 0xff, 0x73, 0x8c, 0x00, /* 45% */
	0x00, 0x7f, 0xff, 0x80, 0x7f, 0x00, 0x7f, 0x00, 0x80, 0xff, 0x7f, 0x00, 0x7f, 0x00, 0xff, 0x80, 0x00, 0x7f, 0x7f, 0x00, 0xff, 0x80, 0x7f, 0x00, /* 50% */
	0x00, 0x73, 0xff, 0x8c, 0x73, 0x00, 0x73, 0x00, 0x8c, 0xff, 0x73, 0x00, 0x73, 0x00, 0xff, 0x8c, 0x00, 0x73, 0x73, 0x00, 0xff, 0x8c, 0x73, 0x00, /* 55% */
	0x00, 0x66, 0xff, 0x99, 0x66, 0x00, 0x66, 0x00, 0x99, 0xff, 0x66, 0x00, 0x66, 0x00, 0xff, 0x99, 0x00, 0x66, 0x66, 0x00, 0xff, 0x99, 0x66, 0x00, /* 60% */

	//Chartreuse Green
	0x19, 0xe5, 0xff, 0x33, 0xcc, 0x00, 0xe5, 0x19, 0x33, 0xff, 0xcc, 0x00, 0xe5, 0x19, 0xff, 0x33, 0x00, 0xcc, 0xe5, 0x19, 0xff, 0x33, 0xcc, 0x00, /* 20% */
	0x20, 0xdf, 0xff, 0x40, 0xbf, 0x00, 0xdf, 0x20, 0x40, 0xff, 0xbf, 0x00, 0xdf, 0x20, 0xff, 0x40, 0x00, 0xbf, 0xdf, 0x20, 0xff, 0x40, 0xbf, 0x00, /* 25% */
	0x26, 0xd8, 0xff, 0x4d, 0xb2, 0x00, 0xd8, 0x26, 0x4d, 0xff, 0xb2, 0x00, 0xd8, 0x26, 0xff, 0x4d, 0x00, 0xb2, 0xd8, 0x26, 0xff, 0x4d, 0xb2, 0x00, /* 30% */
	0x2c, 0xd2, 0xff, 0x59, 0xa6, 0x00, 0xd2, 0x2c, 0x59, 0xff, 0xa6, 0x00, 0xd2, 0x2c, 0xff, 0x59, 0x00, 0xa6, 0xd2, 0x2c, 0xff, 0x59, 0xa6, 0x00, /* 35% */
	0x33, 0xcc, 0xff, 0x66, 0x99, 0x00, 0xcc, 0x33, 0x66, 0xff, 0x99, 0x00, 0xcc, 0x33, 0xff, 0x66, 0x00, 0x99, 0xcc, 0x33, 0xff, 0x66, 0x99, 0x00, /* 40% */
	0x39, 0xc5, 0xff, 0x73, 0x8c, 0x00, 0xc5, 0x39, 0x73, 0xff, 0x8c, 0x00, 0xc5, 0x39, 0xff, 0x73, 0x00, 0x8c, 0xc5, 0x39, 0xff, 0x73, 0x8c, 0x00, /* 45% */
	0x40, 0xbf, 0xff, 0x80, 0x7f, 0x00, 0xbf, 0x40, 0x80, 0xff, 0x7f, 0x00, 0xbf, 0x40, 0xff, 0x80, 0x00, 0x7f, 0xbf, 0x40, 0xff, 0x80, 0x7f, 0x00, /* 50% */
	0x46, 0xb9, 0xff, 0x8c, 0x73, 0x00, 0xb9, 0x46, 0x8c, 0xff, 0x73, 0x00, 0xb9, 0x46, 0xff, 0x8c, 0x00, 0x73, 0xb9, 0x46, 0xff, 0x8c, 0x73, 0x00, /* 55% */
	0x4c, 0xb2, 0xff, 0x99, 0x66, 0x00, 0xb2, 0x4c, 0x99, 0xff, 0x66, 0x00, 0xb2, 0x4c, 0xff, 0x99, 0x00, 0x66, 0xb2, 0x4c, 0xff, 0x99, 0x66, 0x00, /* 60% */

	//Yellow
	0x33, 0xff, 0xff, 0x33, 0xcc, 0x00, 0xff, 0x33, 0x33, 0xff, 0xcc, 0x00, 0xff, 0x33, 0xff, 0x33, 0x00, 0xcc, 0xff, 0x33, 0xff, 0x33, 0xcc, 0x00, /* 20% */
	0x40, 0xff, 0xff, 0x40, 0xbf, 0x00, 0xff, 0x40, 0x40, 0xff, 0xbf, 0x00, 0xff, 0x40, 0xff, 0x40, 0x00, 0xbf, 0xff, 0x40, 0xff, 0x40, 0xbf, 0x00, /* 25% */
	0x4d, 0xff, 0xff, 0x4d, 0xb2, 0x00, 0xff, 0x4d, 0x4d, 0xff, 0xb2, 0x00, 0xff, 0x4d, 0xff, 0x4d, 0x00, 0xb2, 0xff, 0x4d, 0xff, 0x4d, 0xb2, 0x00, /* 30% */
	0x59, 0xff, 0xff, 0x59, 0xa6, 0x00, 0xff, 0x59, 0x59, 0xff, 0xa6, 0x00, 0xff, 0x59, 0xff, 0x59, 0x00, 0xa6, 0xff, 0x59, 0xff, 0x59, 0xa6, 0x00, /* 35% */
	0x66, 0xff, 0xff, 0x66, 0x99, 0x00, 0xff, 0x66, 0x66, 0xff, 0x99, 0x00, 0xff, 0x66, 0xff, 0x66, 0x00, 0x99, 0xff, 0x66, 0xff, 0x66, 0x99, 0x00, /* 40% */
	0x73, 0xff, 0xff, 0x73, 0x8c, 0x00, 0xff, 0x73, 0x73, 0xff, 0x8c, 0x00, 0xff, 0x73, 0xff, 0x73, 0x00, 0x8c, 0xff, 0x73, 0xff, 0x73, 0x8c, 0x00, /* 45% */
	0x80, 0xff, 0xff, 0x80, 0x7f, 0x00, 0xff, 0x80, 0x80, 0xff, 0x7f, 0x00, 0xff, 0x80, 0xff, 0x80, 0x00, 0x7f, 0xff, 0x80, 0xff, 0x80, 0x7f, 0x00, /* 50% */
	0x8c, 0xff, 0xff, 0x8c, 0x73, 0x00, 0xff, 0x8c, 0x8c, 0xff, 0x73, 0x00, 0xff, 0x8c, 0xff, 0x8c, 0x00, 0x73, 0xff, 0x8c, 0xff, 0x8c, 0x73, 0x00, /* 55% */
	0x99, 0xff, 0xff, 0x99, 0x66, 0x00, 0xff, 0x99, 0x99, 0xff, 0x66, 0x00, 0xff, 0x99, 0xff, 0x99, 0x00, 0x66, 0xff, 0x99, 0xff, 0x99, 0x66, 0x00, /* 60% */

	//Orange
	0x33, 0xff, 0xe5, 0x19, 0xcc, 0x00, 0xff, 0x33, 0x19, 0xe5, 0xcc, 0x00, 0xff, 0x33, 0xe5, 0x19, 0x00, 0xcc, 0xff, 0x33, 0xe5, 0x19, 0xcc, 0x00, /* 20% */
	0x40, 0xff, 0xdf, 0x20, 0xbf, 0x00, 0xff, 0x40, 0x20, 0xdf, 0xbf, 0x00, 0xff, 0x40, 0xdf, 0x20, 0x00, 0xbf, 0xff, 0x40, 0xdf, 0x20, 0xbf, 0x00, /* 25% */
	0x4d, 0xff, 0xd8, 0x26, 0xb2, 0x00, 0xff, 0x4d, 0x26, 0xd8, 0xb2, 0x00, 0xff, 0x4d, 0xd8, 0x26, 0x00, 0xb2, 0xff, 0x4d, 0xd8, 0x26, 0xb2, 0x00, /* 30% */
	0x59, 0xff, 0xd2, 0x2c, 0xa6, 0x00, 0xff, 0x59, 0x2c, 0xd2, 0xa6, 0x00, 0xff, 0x59, 0xd2, 0x2c, 0x00, 0xa6, 0xff, 0x59, 0xd2, 0x2c, 0xa6, 0x00, /* 35% */
	0x66, 0xff, 0xcc, 0x33, 0x99, 0x00, 0xff, 0x66, 0x33, 0xcc, 0x99, 0x00, 0xff, 0x66, 0xcc, 0x33, 0x00, 0x99, 0xff, 0x66, 0xcc, 0x33, 0x99, 0x00, /* 40% */
	0x73, 0xff, 0xc5, 0x39, 0x8c, 0x00, 0xff, 0x73, 0x39, 0xc5, 0x8c, 0x00, 0xff, 0x73, 0xc5, 0x39, 0x00, 0x8c, 0xff, 0x73, 0xc5, 0x39, 0x8c, 0x00, /* 45% */
	0x80, 0xff, 0xbf, 0x40, 0x7f, 0x00, 0xff, 0x80, 0x40, 0xbf, 0x7f, 0x00, 0xff, 0x80, 0xbf, 0x40, 0x00, 0x7f, 0xff, 0x80, 0xbf, 0x40, 0x7f, 0x00, /* 50% */
	0x8c, 0xff, 0xb9, 0x46, 0x73, 0x00, 0xff, 0x8c, 0x46, 0xb9, 0x73, 0x00, 0xff, 0x8c, 0xb9, 0x46, 0x00, 0x73, 0xff, 0x8c, 0xb9, 0x46, 0x73, 0x00, /* 55% */
	0x99, 0xff, 0xb2, 0x4c, 0x66, 0x00, 0xff, 0x99, 0x4c, 0xb2, 0x66, 0x00, 0xff, 0x99, 0xb2, 0x4c, 0x00, 0x66, 0xff, 0x99, 0xb2, 0x4c, 0x66, 0x00, /* 60% */

	//Red
	0x33, 0xff, 0xcc, 0x00, 0xcc, 0x00, 0xff, 0x33, 0x00, 0xcc, 0xcc, 0x00, 0xff, 0x33, 0xcc, 0x00, 0x00, 0xcc, 0xff, 0x33, 0xcc, 0x00, 0xcc, 0x00, /* 20% */
	0x40, 0xff, 0xbf, 0x00, 0xbf, 0x00, 0xff, 0x40, 0x00, 0xbf, 0xbf, 0x00, 0xff, 0x40, 0xbf, 0x00, 0x00, 0xbf, 0xff, 0x40, 0xbf, 0x00, 0xbf, 0x00, /* 25% */
	0x4d, 0xff, 0xb2, 0x00, 0xb2, 0x00, 0xff, 0x4d, 0x00, 0xb2, 0xb2, 0x00, 0xff, 0x4d, 0xb2, 0x00, 0x00, 0xb2, 0xff, 0x4d, 0xb2, 0x00, 0xb2, 0x00, /* 30% */
	0x59, 0xff, 0xa6, 0x00, 0xa6, 0x00, 0xff, 0x59, 0x00, 0xa6, 0xa6, 0x00, 0xff, 0x59, 0xa6, 0x00, 0x00, 0xa6, 0xff, 0x59, 0xa6, 0x00, 0xa6, 0x00, /* 35% */
	0x66, 0xff, 0x99, 0x00, 0x99, 0x00, 0xff, 0x66, 0x00, 0x99, 0x99, 0x00, 0xff, 0x66, 0x99, 0x00, 0x00, 0x99, 0xff, 0x66, 0x99, 0x00, 0x99, 0x00, /* 40% */
	0x73, 0xff, 0x8c, 0x00, 0x8c, 0x00, 0xff, 0x73, 0x00, 0x8c, 0x8c, 0x00, 0xff, 0x73, 0x8c, 0x00, 0x00, 0x8c, 0xff, 0x73, 0x8c, 0x00, 0x8c, 0x00, /* 45% */
	0x80, 0xff, 0x7f, 0x00, 0x7f, 0x00, 0xff, 0x80, 0x00, 0x7f, 0x7f, 0x00, 0xff, 0x80, 0x7f, 0x00, 0x00, 0x7f, 0xff, 0x80, 0x7f, 0x00, 0x7f, 0x00, /* 50% */
	0x8c, 0xff, 0x73, 0x00, 0x73, 0x00, 0xff, 0x8c, 0x00, 0x73, 0x73, 0x00, 0xff, 0x8c, 0x73, 0x00, 0x00, 0x73, 0xff, 0x8c, 0x73, 0x00, 0x73, 0x00, /* 55% */
	0x99, 0xff, 0x66, 0x00, 0x66, 0x00, 0xff, 0x99, 0x00, 0x66, 0x66, 0x00, 0xff, 0x99, 0x66, 0x00, 0x00, 0x66, 0xff, 0x99, 0x66, 0x00, 0x66, 0x00, /* 60% */

	//Rose
	0x33, 0xff, 0xcc, 0x00, 0xe5, 0x19, 0xff, 0x33, 0x00, 0xcc, 0xe5, 0x19, 0xff, 0x33, 0xcc, 0x00, 0x19, 0xe5, 0xff, 0x33, 0xcc, 0x00, 0xe5, 0x19, /* 20% */
	0x40, 0xff, 0xbf, 0x00, 0xdf, 0x20, 0xff, 0x40, 0x00, 0xbf, 0xdf, 0x20, 0xff, 0x40, 0xbf, 0x00, 0x20, 0xdf, 0xff, 0x40, 0xbf, 0x00, 0xdf, 0x20, /* 25% */
	0x4d, 0xff, 0xb2, 0x00, 0xd8, 0x26, 0xff, 0x4d, 0x00, 0xb2, 0xd8, 0x26, 0xff, 0x4d, 0xb2, 0x00, 0x26, 0xd8, 0xff, 0x4d, 0xb2, 0x00, 0xd8, 0x26, /* 30% */
	0x59, 0xff, 0xa6, 0x00, 0xd2, 0x2c, 0xff, 0x59, 0x00, 0xa6, 0xd2, 0x2c, 0xff, 0x59, 0xa6, 0x00, 0x2c, 0xd2, 0xff, 0x59, 0xa6, 0x00, 0xd2, 0x2c, /* 35% */
	0x66, 0xff, 0x99, 0x00, 0xcc, 0x33, 0xff, 0x66, 0x00, 0x99, 0xcc, 0x33, 0xff, 0x66, 0x99, 0x00, 0x33, 0xcc, 0xff, 0x66, 0x99, 0x00, 0xcc, 0x33, /* 40% */
	0x73, 0xff, 0x8c, 0x00, 0xc5, 0x39, 0xff, 0x73, 0x00, 0x8c, 0xc5, 0x39, 0xff, 0x73, 0x8c, 0x00, 0x39, 0xc5, 0xff, 0x73, 0x8c, 0x00, 0xc5, 0x39, /* 45% */
	0x80, 0xff, 0x7f, 0x00, 0xbf, 0x40, 0xff, 0x80, 0x00, 0x7f, 0xbf, 0x40, 0xff, 0x80, 0x7f, 0x00, 0x40, 0xbf, 0xff, 0x80, 0x7f, 0x00, 0xbf, 0x40, /* 50% */
	0x8c, 0xff, 0x73, 0x00, 0xb9, 0x46, 0xff, 0x8c, 0x00, 0x73, 0xb9, 0x46, 0xff, 0x8c, 0x73, 0x00, 0x46, 0xb9, 0xff, 0x8c, 0x73, 0x00, 0xb9, 0x46, /* 55% */
	0x99, 0xff, 0x66, 0x00, 0xb2, 0x4c, 0xff, 0x99, 0x00, 0x66, 0xb2, 0x4c, 0xff, 0x99, 0x66, 0x00, 0x4c, 0xb2, 0xff, 0x99, 0x66, 0x00, 0xb2, 0x4c, /* 60% */

	//Magenta
	0x33, 0xff, 0xcc, 0x00, 0xff, 0x33, 0xff, 0x33, 0x00, 0xcc, 0xff, 0x33, 0xff, 0x33, 0xcc, 0x00, 0x33, 0xff, 0xff, 0x33, 0xcc, 0x00, 0xff, 0x33, /* 20% */
	0x40, 0xff, 0xbf, 0x00, 0xff, 0x40, 0xff, 0x40, 0x00, 0xbf, 0xff, 0x40, 0xff, 0x40, 0xbf, 0x00, 0x40, 0xff, 0xff, 0x40, 0xbf, 0x00, 0xff, 0x40, /* 25% */
	0x4d, 0xff, 0xb2, 0x00, 0xff, 0x4d, 0xff, 0x4d, 0x00, 0xb2, 0xff, 0x4d, 0xff, 0x4d, 0xb2, 0x00, 0x4d, 0xff, 0xff, 0x4d, 0xb2, 0x00, 0xff, 0x4d, /* 30% */
	0x59, 0xff, 0xa6, 0x00, 0xff, 0x59, 0xff, 0x59, 0x00, 0xa6, 0xff, 0x59, 0xff, 0x59, 0xa6, 0x00, 0x59, 0xff, 0xff, 0x59, 0xa6, 0x00, 0xff, 0x59, /* 35% */
	0x66, 0xff, 0x99, 0x00, 0xff, 0x66, 0xff, 0x66, 0x00, 0x99, 0xff, 0x66, 0xff, 0x66, 0x99, 0x00, 0x66, 0xff, 0xff, 0x66, 0x99, 0x00, 0xff, 0x66, /* 40% */
	0x73, 0xff, 0x8c, 0x00, 0xff, 0x73, 0xff, 0x73, 0x00, 0x8c, 0xff, 0x73, 0xff, 0x73, 0x8c, 0x00, 0x73, 0xff, 0xff, 0x73, 0x8c, 0x00, 0xff, 0x73, /* 45% */
	0x80, 0xff, 0x7f, 0x00, 0xff, 0x80, 0xff, 0x80, 0x00, 0x7f, 0xff, 0x80, 0xff, 0x80, 0x7f, 0x00, 0x80, 0xff, 0xff, 0x80, 0x7f, 0x00, 0xff, 0x80, /* 50% */
	0x8c, 0xff, 0x73, 0x00, 0xff, 0x8c, 0xff, 0x8c, 0x00, 0x73, 0xff, 0x8c, 0xff, 0x8c, 0x73, 0x00, 0x8c, 0xff, 0xff, 0x8c, 0x73, 0x00, 0xff, 0x8c, /* 55% */
	0x99, 0xff, 0x66, 0x00, 0xff, 0x99, 0xff, 0x99, 0x00, 0x66, 0xff, 0x99, 0xff, 0x99, 0x66, 0x00, 0x99, 0xff, 0xff, 0x99, 0x66, 0x00, 0xff, 0x99, /* 60% */

	//Violet
	0x19, 0xe5, 0xcc, 0x00, 0xff, 0x33, 0xe5, 0x19, 0x00, 0xcc, 0xff, 0x33, 0xe5, 0x19, 0xcc, 0x00, 0x33, 0xff, 0xe5, 0x19, 0xcc, 0x00, 0xff, 0x33, /* 20% */
	0x20, 0xdf, 0xbf, 0x00, 0xff, 0x40, 0xdf, 0x20, 0x00, 0xbf, 0xff, 0x40, 0xdf, 0x20, 0xbf, 0x00, 0x40, 0xff, 0xdf, 0x20, 0xbf, 0x00, 0xff, 0x40, /* 25% */
	0x26, 0xd8, 0xb2, 0x00, 0xff, 0x4d, 0xd8, 0x26, 0x00, 0xb2, 0xff, 0x4d, 0xd8, 0x26, 0xb2, 0x00, 0x4d, 0xff, 0xd8, 0x26, 0xb2, 0x00, 0xff, 0x4d, /* 30% */
	0x2c, 0xd2, 0xa6, 0x00, 0xff, 0x59, 0xd2, 0x2c, 0x00, 0xa6, 0xff, 0x59, 0xd2, 0x2c, 0xa6, 0x00, 0x59, 0xff, 0xd2, 0x2c, 0xa6, 0x00, 0xff, 0x59, /* 35% */
	0x33, 0xcc, 0x99, 0x00, 0xff, 0x66, 0xcc, 0x33, 0x00, 0x99, 0xff, 0x66, 0xcc, 0x33, 0x99, 0x00, 0x66, 0xff, 0xcc, 0x33, 0x99, 0x00, 0xff, 0x66, /* 40% */
	0x39, 0xc5, 0x8c, 0x00, 0xff, 0x73, 0xc5, 0x39, 0x00, 0x8c, 0xff, 0x73, 0xc5, 0x39, 0x8c, 0x00, 0x73, 0xff, 0xc5, 0x39, 0x8c, 0x00, 0xff, 0x73, /* 45% */
	0x40, 0xbf, 0x7f, 0x00, 0xff, 0x80, 0xbf, 0x40, 0x00, 0x7f, 0xff, 0x80, 0xbf, 0x40, 0x7f, 0x00, 0x80, 0xff, 0xbf, 0x40, 0x7f, 0x00, 0xff, 0x80, /* 50% */
	0x46, 0xb9, 0x73, 0x00, 0xff, 0x8c, 0xb9, 0x46, 0x00, 0x73, 0xff, 0x8c, 0xb9, 0x46, 0x73, 0x00, 0x8c, 0xff, 0xb9, 0x46, 0x73, 0x00, 0xff, 0x8c, /* 55% */
	0x4c, 0xb2, 0x66, 0x00, 0xff, 0x99, 0xb2, 0x4c, 0x00, 0x66, 0xff, 0x99, 0xb2, 0x4c, 0x66, 0x00, 0x99, 0xff, 0xb2, 0x4c, 0x66, 0x00, 0xff, 0x99, /* 60% */
};

static inline int get_hbm_index(int idx)
{
	int i = 0;
	int idx_list[] = {
		10000	/* idx < 10000: HBM_OFF */
			/* idx >= 10000: HBM_AOLCE_1 */
	};

	while (i < ARRAY_SIZE(idx_list)) {
		if (idx < idx_list[i])
			break;
		i++;
	}

	return i;
}

static unsigned char GRAYSCALE_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0x4c, //ascr_skin_Rr
	0x4c, //ascr_skin_Rg
	0x4c, //ascr_skin_Rb
	0xe2, //ascr_skin_Yr
	0xe2, //ascr_skin_Yg
	0xe2, //ascr_skin_Yb
	0x69, //ascr_skin_Mr
	0x69, //ascr_skin_Mg
	0x69, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0xb3, //ascr_Cr
	0x4c, //ascr_Rr
	0xb3, //ascr_Cg
	0x4c, //ascr_Rg
	0xb3, //ascr_Cb
	0x4c, //ascr_Rb
	0x69, //ascr_Mr
	0x96, //ascr_Gr
	0x69, //ascr_Mg
	0x96, //ascr_Gg
	0x69, //ascr_Mb
	0x96, //ascr_Gb
	0xe2, //ascr_Yr
	0x1d, //ascr_Br
	0xe2, //ascr_Yg
	0x1d, //ascr_Bg
	0xe2, //ascr_Yb
	0x1d, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char GRAYSCALE_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char GRAYSCALE_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char GRAYSCALE_NEGATIVE_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xb3, //ascr_skin_Rr
	0xb3, //ascr_skin_Rg
	0xb3, //ascr_skin_Rb
	0x1d, //ascr_skin_Yr
	0x1d, //ascr_skin_Yg
	0x1d, //ascr_skin_Yb
	0x96, //ascr_skin_Mr
	0x96, //ascr_skin_Mg
	0x96, //ascr_skin_Mb
	0x00, //ascr_skin_Wr
	0x00, //ascr_skin_Wg
	0x00, //ascr_skin_Wb
	0x4c, //ascr_Cr
	0xb3, //ascr_Rr
	0x4c, //ascr_Cg
	0xb3, //ascr_Rg
	0x4c, //ascr_Cb
	0xb3, //ascr_Rb
	0x96, //ascr_Mr
	0x69, //ascr_Gr
	0x96, //ascr_Mg
	0x69, //ascr_Gg
	0x96, //ascr_Mb
	0x69, //ascr_Gb
	0x1d, //ascr_Yr
	0xe2, //ascr_Br
	0x1d, //ascr_Yg
	0xe2, //ascr_Bg
	0x1d, //ascr_Yb
	0xe2, //ascr_Bb
	0x00, //ascr_Wr
	0xff, //ascr_Kr
	0x00, //ascr_Wg
	0xff, //ascr_Kg
	0x00, //ascr_Wb
	0xff, //ascr_Kb
};

static unsigned char GRAYSCALE_NEGATIVE_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char GRAYSCALE_NEGATIVE_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char SCREEN_CURTAIN_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0x00, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0x00, //ascr_skin_Yr
	0x00, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0x00, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0x00, //ascr_skin_Mb
	0x00, //ascr_skin_Wr
	0x00, //ascr_skin_Wg
	0x00, //ascr_skin_Wb
	0x00, //ascr_Cr
	0x00, //ascr_Rr
	0x00, //ascr_Cg
	0x00, //ascr_Rg
	0x00, //ascr_Cb
	0x00, //ascr_Rb
	0x00, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0x00, //ascr_Gg
	0x00, //ascr_Mb
	0x00, //ascr_Gb
	0x00, //ascr_Yr
	0x00, //ascr_Br
	0x00, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0x00, //ascr_Bb
	0x00, //ascr_Wr
	0x00, //ascr_Kr
	0x00, //ascr_Wg
	0x00, //ascr_Kg
	0x00, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char SCREEN_CURTAIN_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char SCREEN_CURTAIN_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char HDR_VIDEO_1_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xd0, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x50, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xd0, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xd0, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xf0, //ascr_Yg
	0x00, //ascr_Bg
	0x50, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HDR_VIDEO_1_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x0f, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x00, //de_maxplus 11
	0x40,
	0x00, //de_maxminus 11
	0x40,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0xd0,
	0x00, //curve_1_b
	0x1a, //curve_1_a
	0x00, //curve_2_b
	0x1a, //curve_2_a
	0x00, //curve_3_b
	0x1a, //curve_3_a
	0x00, //curve_4_b
	0x1a, //curve_4_a
	0x01, //curve_5_b
	0x18, //curve_5_a
	0x01, //curve_6_b
	0x18, //curve_6_a
	0x01, //curve_7_b
	0x18, //curve_7_a
	0x01, //curve_8_b
	0x18, //curve_8_a
	0x01, //curve_9_b
	0x18, //curve_9_a
	0x03, //curve10_b
	0x16, //curve10_a
	0x03, //curve11_b
	0x16, //curve11_a
	0x04, //curve12_b
	0x16, //curve12_a
	0x0e, //curve13_b
	0xa2, //curve13_a
	0x0e, //curve14_b
	0xa2, //curve14_a
	0x0f, //curve15_b
	0xa2, //curve15_a
	0x0f, //curve16_b
	0xa2, //curve16_a
	0x34, //curve17_b
	0xb4, //curve17_a
	0x3e, //curve18_b
	0xb8, //curve18_a
	0x50, //curve19_b
	0xbf, //curve19_a
	0x1a, //curve20_b
	0xb1, //curve20_a
	0x6a, //curve21_b
	0x18, //curve21_a
	0xff, //curve22_b
	0x00, //curve22_a
	0xff, //curve23_b
	0x00, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char HDR_VIDEO_1_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char HDR_VIDEO_2_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xd0, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x50, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xd0, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xd0, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xf0, //ascr_Yg
	0x00, //ascr_Bg
	0x50, //ascr_Yb
	0xe0, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HDR_VIDEO_2_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x0f, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x00, //de_maxplus 11
	0x40,
	0x00, //de_maxminus 11
	0x40,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0xd0,
	0x00, //curve_1_b
	0x1a, //curve_1_a
	0x00, //curve_2_b
	0x1a, //curve_2_a
	0x00, //curve_3_b
	0x1a, //curve_3_a
	0x00, //curve_4_b
	0x1a, //curve_4_a
	0x01, //curve_5_b
	0x18, //curve_5_a
	0x01, //curve_6_b
	0x18, //curve_6_a
	0x01, //curve_7_b
	0x18, //curve_7_a
	0x01, //curve_8_b
	0x18, //curve_8_a
	0x01, //curve_9_b
	0x18, //curve_9_a
	0x03, //curve10_b
	0x16, //curve10_a
	0x03, //curve11_b
	0x16, //curve11_a
	0x04, //curve12_b
	0x16, //curve12_a
	0x0e, //curve13_b
	0xa2, //curve13_a
	0x0e, //curve14_b
	0xa2, //curve14_a
	0x0f, //curve15_b
	0xa2, //curve15_a
	0x0f, //curve16_b
	0xa2, //curve16_a
	0x34, //curve17_b
	0xb4, //curve17_a
	0x3e, //curve18_b
	0xb8, //curve18_a
	0x5d, //curve19_b
	0xc4, //curve19_a
	0x10, //curve20_b
	0xb0, //curve20_a
	0x9a, //curve21_b
	0x10, //curve21_a
	0xff, //curve22_b
	0x00, //curve22_a
	0xff, //curve23_b
	0x00, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char HDR_VIDEO_2_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char HDR_VIDEO_3_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HDR_VIDEO_3_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char HDR_VIDEO_3_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x00, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char VIDEO_ENHANCER_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x48, //ascr_skin_Rg
	0x58, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char VIDEO_ENHANCER_2[] = {
	0xDE,
	0x88, //lce_on gain 0 000 0000
	0x18, //lce_color_gain 00 0000
	0xff, //lce_min_ref_offset
	0xc0, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x40,
	0x01, //lce_ref_gain 9
	0x00,
	0x66, //lce_block_size h v 0000 0000
	0x05, //lce_dark_th 000
	0x01, //lce_reduct_slope 0000
	0x46, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x04, //lce_large_w
	0x06, //lce_med_w
	0x06, //lce_small_w
	0x00, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x07, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x00, //de_maxplus 11
	0x40,
	0x00, //de_maxminus 11
	0x40,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char VIDEO_ENHANCER_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3f, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char VIDEO_ENHANCER_THIRD_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x48, //ascr_skin_Rg
	0x58, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char VIDEO_ENHANCER_THIRD_2[] = {
	0xDE,
	0x81, //lce_on gain 0 000 0000
	0x18, //lce_color_gain 00 0000
	0xff, //lce_min_ref_offset
	0xc0, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x40,
	0x01, //lce_ref_gain 9
	0x00,
	0x66, //lce_block_size h v 0000 0000
	0x05, //lce_dark_th 000
	0x01, //lce_reduct_slope 0000
	0x46, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x04, //lce_large_w
	0x06, //lce_med_w
	0x06, //lce_small_w
	0x00, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x07, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x00, //de_maxplus 11
	0x40,
	0x00, //de_maxminus 11
	0x40,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x17, //curve20_b
	0xa6, //curve20_a
	0x04, //curve21_b
	0x21, //curve21_a
	0x0a, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char VIDEO_ENHANCER_THIRD_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3f, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

////////////////// UI /// /////////////////////
static unsigned char STANDARD_UI_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xf1, //ascr_skin_Rr
	0x2f, //ascr_skin_Rg
	0x2e, //ascr_skin_Rb
	0xf2, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x45, //ascr_skin_Yb
	0xfb, //ascr_skin_Mr
	0x48, //ascr_skin_Mg
	0xe7, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xf1, //ascr_Rr
	0xef, //ascr_Cg
	0x2f, //ascr_Rg
	0xe9, //ascr_Cb
	0x2e, //ascr_Rb
	0xfb, //ascr_Mr
	0x00, //ascr_Gr
	0x48, //ascr_Mg
	0xdf, //ascr_Gg
	0xe7, //ascr_Mb
	0x00, //ascr_Gb
	0xf2, //ascr_Yr
	0x30, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x45, //ascr_Yb
	0xdf, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char STANDARD_UI_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char STANDARD_UI_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NATURAL_UI_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xd2, //ascr_skin_Rr
	0x26, //ascr_skin_Rg
	0x26, //ascr_skin_Rb
	0xf3, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x58, //ascr_skin_Yb
	0xdd, //ascr_skin_Mr
	0x41, //ascr_skin_Mg
	0xe1, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x94, //ascr_Cr
	0xd2, //ascr_Rr
	0xf3, //ascr_Cg
	0x26, //ascr_Rg
	0xea, //ascr_Cb
	0x26, //ascr_Rb
	0xdd, //ascr_Mr
	0x8a, //ascr_Gr
	0x41, //ascr_Mg
	0xe7, //ascr_Gg
	0xe1, //ascr_Mb
	0x4e, //ascr_Gb
	0xf3, //ascr_Yr
	0x2a, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x58, //ascr_Yb
	0xdc, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char NATURAL_UI_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NATURAL_UI_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char DYNAMIC_UI_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x70, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf4, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char DYNAMIC_UI_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x03, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char DYNAMIC_UI_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char MOVIE_UI_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char MOVIE_UI_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char MOVIE_UI_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_UI_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_UI_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char AUTO_UI_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

////////////////// GALLERY /////////////////////
static unsigned char STANDARD_GALLERY_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xf1, //ascr_skin_Rr
	0x2f, //ascr_skin_Rg
	0x2e, //ascr_skin_Rb
	0xf2, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x45, //ascr_skin_Yb
	0xfb, //ascr_skin_Mr
	0x48, //ascr_skin_Mg
	0xe7, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xf1, //ascr_Rr
	0xef, //ascr_Cg
	0x2f, //ascr_Rg
	0xe9, //ascr_Cb
	0x2e, //ascr_Rb
	0xfb, //ascr_Mr
	0x00, //ascr_Gr
	0x48, //ascr_Mg
	0xdf, //ascr_Gg
	0xe7, //ascr_Mb
	0x00, //ascr_Gb
	0xf2, //ascr_Yr
	0x30, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x45, //ascr_Yb
	0xdf, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char STANDARD_GALLERY_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char STANDARD_GALLERY_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NATURAL_GALLERY_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xd2, //ascr_skin_Rr
	0x26, //ascr_skin_Rg
	0x26, //ascr_skin_Rb
	0xf3, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x58, //ascr_skin_Yb
	0xdd, //ascr_skin_Mr
	0x41, //ascr_skin_Mg
	0xe1, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x94, //ascr_Cr
	0xd2, //ascr_Rr
	0xf3, //ascr_Cg
	0x26, //ascr_Rg
	0xea, //ascr_Cb
	0x26, //ascr_Rb
	0xdd, //ascr_Mr
	0x8a, //ascr_Gr
	0x41, //ascr_Mg
	0xe7, //ascr_Gg
	0xe1, //ascr_Mb
	0x4e, //ascr_Gb
	0xf3, //ascr_Yr
	0x2a, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x58, //ascr_Yb
	0xdc, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char NATURAL_GALLERY_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NATURAL_GALLERY_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char DYNAMIC_GALLERY_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x70, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf4, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char DYNAMIC_GALLERY_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x07, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char DYNAMIC_GALLERY_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char MOVIE_GALLERY_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char MOVIE_GALLERY_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char MOVIE_GALLERY_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_GALLERY_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x6a, //ascr_skin_cb
	0x9a, //ascr_skin_cr
	0x25, //ascr_dist_up
	0x1a, //ascr_dist_down
	0x16, //ascr_dist_right
	0x2a, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x37,
	0x5a,
	0x00, //ascr_div_down
	0x4e,
	0xc5,
	0x00, //ascr_div_right
	0x5d,
	0x17,
	0x00, //ascr_div_left
	0x30,
	0xc3,
	0xff, //ascr_skin_Rr
	0x35, //ascr_skin_Rg
	0x4f, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf0, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xd8, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xd9, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xe0, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xf6, //ascr_Cb
	0x00, //ascr_Rb
	0xd8, //ascr_Mr
	0x3b, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xd9, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x14, //ascr_Br
	0xf9, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_GALLERY_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x0c, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char AUTO_GALLERY_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

////////////////// VIDEO /////////////////////
static unsigned char STANDARD_VIDEO_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xf1, //ascr_skin_Rr
	0x2f, //ascr_skin_Rg
	0x2e, //ascr_skin_Rb
	0xf2, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x45, //ascr_skin_Yb
	0xfb, //ascr_skin_Mr
	0x48, //ascr_skin_Mg
	0xe7, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xf1, //ascr_Rr
	0xef, //ascr_Cg
	0x2f, //ascr_Rg
	0xe9, //ascr_Cb
	0x2e, //ascr_Rb
	0xfb, //ascr_Mr
	0x00, //ascr_Gr
	0x48, //ascr_Mg
	0xdf, //ascr_Gg
	0xe7, //ascr_Mb
	0x00, //ascr_Gb
	0xf2, //ascr_Yr
	0x30, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x45, //ascr_Yb
	0xdf, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char STANDARD_VIDEO_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char STANDARD_VIDEO_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NATURAL_VIDEO_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xd2, //ascr_skin_Rr
	0x26, //ascr_skin_Rg
	0x26, //ascr_skin_Rb
	0xf3, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x58, //ascr_skin_Yb
	0xdd, //ascr_skin_Mr
	0x41, //ascr_skin_Mg
	0xe1, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x94, //ascr_Cr
	0xd2, //ascr_Rr
	0xf3, //ascr_Cg
	0x26, //ascr_Rg
	0xea, //ascr_Cb
	0x26, //ascr_Rb
	0xdd, //ascr_Mr
	0x8a, //ascr_Gr
	0x41, //ascr_Mg
	0xe7, //ascr_Gg
	0xe1, //ascr_Mb
	0x4e, //ascr_Gb
	0xf3, //ascr_Yr
	0x2a, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x58, //ascr_Yb
	0xdc, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char NATURAL_VIDEO_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NATURAL_VIDEO_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char DYNAMIC_VIDEO_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x70, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf4, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char DYNAMIC_VIDEO_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x07, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x00, //de_maxplus 11
	0x40,
	0x00, //de_maxminus 11
	0x40,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char DYNAMIC_VIDEO_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char MOVIE_VIDEO_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char MOVIE_VIDEO_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char MOVIE_VIDEO_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_VIDEO_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x70, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf4, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_VIDEO_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x0f, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x00, //de_maxplus 11
	0x40,
	0x00, //de_maxminus 11
	0x40,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char AUTO_VIDEO_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

////////////////// VT /////////////////////
static unsigned char STANDARD_VT_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xf1, //ascr_skin_Rr
	0x2f, //ascr_skin_Rg
	0x2e, //ascr_skin_Rb
	0xf2, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x45, //ascr_skin_Yb
	0xfb, //ascr_skin_Mr
	0x48, //ascr_skin_Mg
	0xe7, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xf1, //ascr_Rr
	0xef, //ascr_Cg
	0x2f, //ascr_Rg
	0xe9, //ascr_Cb
	0x2e, //ascr_Rb
	0xfb, //ascr_Mr
	0x00, //ascr_Gr
	0x48, //ascr_Mg
	0xdf, //ascr_Gg
	0xe7, //ascr_Mb
	0x00, //ascr_Gb
	0xf2, //ascr_Yr
	0x30, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x45, //ascr_Yb
	0xdf, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char STANDARD_VT_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char STANDARD_VT_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NATURAL_VT_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xd2, //ascr_skin_Rr
	0x26, //ascr_skin_Rg
	0x26, //ascr_skin_Rb
	0xf3, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x58, //ascr_skin_Yb
	0xdd, //ascr_skin_Mr
	0x41, //ascr_skin_Mg
	0xe1, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x94, //ascr_Cr
	0xd2, //ascr_Rr
	0xf3, //ascr_Cg
	0x26, //ascr_Rg
	0xea, //ascr_Cb
	0x26, //ascr_Rb
	0xdd, //ascr_Mr
	0x8a, //ascr_Gr
	0x41, //ascr_Mg
	0xe7, //ascr_Gg
	0xe1, //ascr_Mb
	0x4e, //ascr_Gb
	0xf3, //ascr_Yr
	0x2a, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x58, //ascr_Yb
	0xdc, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char NATURAL_VT_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NATURAL_VT_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char DYNAMIC_VT_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x70, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf4, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char DYNAMIC_VT_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x07, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char DYNAMIC_VT_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char MOVIE_VT_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char MOVIE_VT_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char MOVIE_VT_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_VT_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_VT_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x0c, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char AUTO_VT_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};


static unsigned char BYPASS_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char BYPASS_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char BYPASS_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x00, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

////////////////// CAMERA /////////////////////
static unsigned char STANDARD_CAMERA_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xf1, //ascr_skin_Rr
	0x2f, //ascr_skin_Rg
	0x2e, //ascr_skin_Rb
	0xf2, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x45, //ascr_skin_Yb
	0xfb, //ascr_skin_Mr
	0x48, //ascr_skin_Mg
	0xe7, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xf1, //ascr_Rr
	0xef, //ascr_Cg
	0x2f, //ascr_Rg
	0xe9, //ascr_Cb
	0x2e, //ascr_Rb
	0xfb, //ascr_Mr
	0x00, //ascr_Gr
	0x48, //ascr_Mg
	0xdf, //ascr_Gg
	0xe7, //ascr_Mb
	0x00, //ascr_Gb
	0xf2, //ascr_Yr
	0x30, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x45, //ascr_Yb
	0xdf, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char STANDARD_CAMERA_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char STANDARD_CAMERA_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NATURAL_CAMERA_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xd2, //ascr_skin_Rr
	0x26, //ascr_skin_Rg
	0x26, //ascr_skin_Rb
	0xf3, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x58, //ascr_skin_Yb
	0xdd, //ascr_skin_Mr
	0x41, //ascr_skin_Mg
	0xe1, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x94, //ascr_Cr
	0xd2, //ascr_Rr
	0xf3, //ascr_Cg
	0x26, //ascr_Rg
	0xea, //ascr_Cb
	0x26, //ascr_Rb
	0xdd, //ascr_Mr
	0x8a, //ascr_Gr
	0x41, //ascr_Mg
	0xe7, //ascr_Gg
	0xe1, //ascr_Mb
	0x4e, //ascr_Gb
	0xf3, //ascr_Yr
	0x2a, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x58, //ascr_Yb
	0xdc, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char NATURAL_CAMERA_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NATURAL_CAMERA_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char DYNAMIC_CAMERA_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x70, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf4, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char DYNAMIC_CAMERA_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x03, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char DYNAMIC_CAMERA_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char MOVIE_CAMERA_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char MOVIE_CAMERA_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char MOVIE_CAMERA_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_CAMERA_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x6a, //ascr_skin_cb
	0x9a, //ascr_skin_cr
	0x25, //ascr_dist_up
	0x1a, //ascr_dist_down
	0x16, //ascr_dist_right
	0x2a, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x37,
	0x5a,
	0x00, //ascr_div_down
	0x4e,
	0xc5,
	0x00, //ascr_div_right
	0x5d,
	0x17,
	0x00, //ascr_div_left
	0x30,
	0xc3,
	0xff, //ascr_skin_Rr
	0x35, //ascr_skin_Rg
	0x4f, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf0, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xd8, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xd9, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xe0, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xf6, //ascr_Cb
	0x00, //ascr_Rb
	0xd8, //ascr_Mr
	0x3b, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xd9, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x14, //ascr_Br
	0xf9, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_CAMERA_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x00, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char AUTO_CAMERA_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NEGATIVE_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0x00, //ascr_skin_Rr
	0xff, //ascr_skin_Rg
	0xff, //ascr_skin_Rb
	0x00, //ascr_skin_Yr
	0x00, //ascr_skin_Yg
	0xff, //ascr_skin_Yb
	0x00, //ascr_skin_Mr
	0xff, //ascr_skin_Mg
	0x00, //ascr_skin_Mb
	0x00, //ascr_skin_Wr
	0x00, //ascr_skin_Wg
	0x00, //ascr_skin_Wb
	0xff, //ascr_Cr
	0x00, //ascr_Rr
	0x00, //ascr_Cg
	0xff, //ascr_Rg
	0x00, //ascr_Cb
	0xff, //ascr_Rb
	0x00, //ascr_Mr
	0xff, //ascr_Gr
	0xff, //ascr_Mg
	0x00, //ascr_Gg
	0x00, //ascr_Mb
	0xff, //ascr_Gb
	0x00, //ascr_Yr
	0xff, //ascr_Br
	0x00, //ascr_Yg
	0xff, //ascr_Bg
	0xff, //ascr_Yb
	0x00, //ascr_Bb
	0x00, //ascr_Wr
	0xff, //ascr_Kr
	0x00, //ascr_Wg
	0xff, //ascr_Kg
	0x00, //ascr_Wb
	0xff, //ascr_Kb
};

static unsigned char NEGATIVE_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NEGATIVE_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char COLOR_BLIND_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char COLOR_BLIND_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char COLOR_BLIND_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char LIGHT_NOTIFICATION_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x13, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf9, //ascr_skin_Yg
	0x13, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x60, //ascr_skin_Mg
	0xac, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xac, //ascr_skin_Wb
	0x66, //ascr_Cr
	0xff, //ascr_Rr
	0xf9, //ascr_Cg
	0x60, //ascr_Rg
	0xac, //ascr_Cb
	0x13, //ascr_Rb
	0xff, //ascr_Mr
	0x66, //ascr_Gr
	0x60, //ascr_Mg
	0xf9, //ascr_Gg
	0xac, //ascr_Mb
	0x13, //ascr_Gb
	0xff, //ascr_Yr
	0x66, //ascr_Br
	0xf9, //ascr_Yg
	0x60, //ascr_Bg
	0x13, //ascr_Yb
	0xac, //ascr_Bb
	0xff, //ascr_Wr
	0x66, //ascr_Kr
	0xf9, //ascr_Wg
	0x60, //ascr_Kg
	0xac, //ascr_Wb
	0x13, //ascr_Kb
};

static unsigned char LIGHT_NOTIFICATION_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char LIGHT_NOTIFICATION_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NIGHT_MODE_1[] = {
	0xDF,
	0x20, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char NIGHT_MODE_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NIGHT_MODE_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char COLOR_LENS_1[] = {
	0xDF,
	0x20, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char COLOR_LENS_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char COLOR_LENS_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

////////////////// BROWSER /////////////////////
static unsigned char STANDARD_BROWSER_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xf1, //ascr_skin_Rr
	0x2f, //ascr_skin_Rg
	0x2e, //ascr_skin_Rb
	0xf2, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x45, //ascr_skin_Yb
	0xfb, //ascr_skin_Mr
	0x48, //ascr_skin_Mg
	0xe7, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xf1, //ascr_Rr
	0xef, //ascr_Cg
	0x2f, //ascr_Rg
	0xe9, //ascr_Cb
	0x2e, //ascr_Rb
	0xfb, //ascr_Mr
	0x00, //ascr_Gr
	0x48, //ascr_Mg
	0xdf, //ascr_Gg
	0xe7, //ascr_Mb
	0x00, //ascr_Gb
	0xf2, //ascr_Yr
	0x30, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x45, //ascr_Yb
	0xdf, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char STANDARD_BROWSER_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char STANDARD_BROWSER_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NATURAL_BROWSER_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xd2, //ascr_skin_Rr
	0x26, //ascr_skin_Rg
	0x26, //ascr_skin_Rb
	0xf3, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x58, //ascr_skin_Yb
	0xdd, //ascr_skin_Mr
	0x41, //ascr_skin_Mg
	0xe1, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x94, //ascr_Cr
	0xd2, //ascr_Rr
	0xf3, //ascr_Cg
	0x26, //ascr_Rg
	0xea, //ascr_Cb
	0x26, //ascr_Rb
	0xdd, //ascr_Mr
	0x8a, //ascr_Gr
	0x41, //ascr_Mg
	0xe7, //ascr_Gg
	0xe1, //ascr_Mb
	0x4e, //ascr_Gb
	0xf3, //ascr_Yr
	0x2a, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x58, //ascr_Yb
	0xdc, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char NATURAL_BROWSER_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NATURAL_BROWSER_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char DYNAMIC_BROWSER_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x70, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf4, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char DYNAMIC_BROWSER_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x03, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char DYNAMIC_BROWSER_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char MOVIE_BROWSER_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char MOVIE_BROWSER_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char MOVIE_BROWSER_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_BROWSER_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x6a, //ascr_skin_cb
	0x9a, //ascr_skin_cr
	0x25, //ascr_dist_up
	0x1a, //ascr_dist_down
	0x16, //ascr_dist_right
	0x2a, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x37,
	0x5a,
	0x00, //ascr_div_down
	0x4e,
	0xc5,
	0x00, //ascr_div_right
	0x5d,
	0x17,
	0x00, //ascr_div_left
	0x30,
	0xc3,
	0xff, //ascr_skin_Rr
	0x48, //ascr_skin_Rg
	0x58, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf8, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_BROWSER_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char AUTO_BROWSER_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

////////////////// eBOOK /////////////////////
static unsigned char AUTO_EBOOK_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xe9, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xf9, //ascr_Wg
	0x00, //ascr_Kg
	0xe9, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_EBOOK_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char AUTO_EBOOK_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char DYNAMIC_EBOOK_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x70, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf4, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char DYNAMIC_EBOOK_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x03, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char DYNAMIC_EBOOK_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char STANDARD_EBOOK_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xf1, //ascr_skin_Rr
	0x2f, //ascr_skin_Rg
	0x2e, //ascr_skin_Rb
	0xf2, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x45, //ascr_skin_Yb
	0xfb, //ascr_skin_Mr
	0x48, //ascr_skin_Mg
	0xe7, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xf1, //ascr_Rr
	0xef, //ascr_Cg
	0x2f, //ascr_Rg
	0xe9, //ascr_Cb
	0x2e, //ascr_Rb
	0xfb, //ascr_Mr
	0x00, //ascr_Gr
	0x48, //ascr_Mg
	0xdf, //ascr_Gg
	0xe7, //ascr_Mb
	0x00, //ascr_Gb
	0xf2, //ascr_Yr
	0x30, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x45, //ascr_Yb
	0xdf, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char STANDARD_EBOOK_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char STANDARD_EBOOK_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NATURAL_EBOOK_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xd2, //ascr_skin_Rr
	0x26, //ascr_skin_Rg
	0x26, //ascr_skin_Rb
	0xf3, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x58, //ascr_skin_Yb
	0xdd, //ascr_skin_Mr
	0x41, //ascr_skin_Mg
	0xe1, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x94, //ascr_Cr
	0xd2, //ascr_Rr
	0xf3, //ascr_Cg
	0x26, //ascr_Rg
	0xea, //ascr_Cb
	0x26, //ascr_Rb
	0xdd, //ascr_Mr
	0x8a, //ascr_Gr
	0x41, //ascr_Mg
	0xe7, //ascr_Gg
	0xe1, //ascr_Mb
	0x4e, //ascr_Gb
	0xf3, //ascr_Yr
	0x2a, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x58, //ascr_Yb
	0xdc, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char NATURAL_EBOOK_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NATURAL_EBOOK_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char MOVIE_EBOOK_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char MOVIE_EBOOK_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char MOVIE_EBOOK_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_EMAIL_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfb, //ascr_skin_Wg
	0xee, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfb, //ascr_Wg
	0x00, //ascr_Kg
	0xee, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_EMAIL_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char AUTO_EMAIL_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_GAME_LOW_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x6a, //ascr_skin_cb
	0x9a, //ascr_skin_cr
	0x25, //ascr_dist_up
	0x1a, //ascr_dist_down
	0x16, //ascr_dist_right
	0x2a, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x37,
	0x5a,
	0x00, //ascr_div_down
	0x4e,
	0xc5,
	0x00, //ascr_div_right
	0x5d,
	0x17,
	0x00, //ascr_div_left
	0x30,
	0xc3,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_GAME_LOW_2[] = {
	0xDE,
	0xa0, //lce_on gain 0 000 0000
	0x18, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0x6e, //lce_illum_gain
	0x00, //lce_ref_offset 9
	0x60,
	0x00, //lce_ref_gain 9
	0x80,
	0x66, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x05, //lce_reduct_slope 0000
	0x46, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x00, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x01, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00,
	0x08,
	0x00,
	0x08,
	0x00,
	0x08,
	0x00,
	0x08,
	0x00,
	0x08,
	0x00,
	0x08,
	0x02,
	0x8c,
	0x02,
	0x8c,
	0x02,
	0x8c,
	0x00,
	0x0a,
	0x00,
	0x0a,
	0x00,
	0x0a,
	0x00,
	0x0a,
	0x23,
	0xa0,
	0x23,
	0xa0,
	0x23,
	0xa0,
	0x23,
	0xa0,
	0x21,
	0x9f,
	0x20,
	0x9e,
	0x20,
	0x9e,
	0x20,
	0x9e,
	0x20,
	0x9e,
	0x20,
	0x9e,
	0x00,
	0xFF,
};

static unsigned char AUTO_GAME_LOW_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x0f, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_GAME_MID_1[] = {
	0xDF,
	0x00,
	0x14,
	0x01,
	0x6a,
	0x9a,
	0x25,
	0x1a,
	0x16,
	0x2a,
	0x00,
	0x37,
	0x5a,
	0x00,
	0x4e,
	0xc5,
	0x00,
	0x5d,
	0x17,
	0x00,
	0x30,
	0xc3,
	0xff,
	0x00,
	0x00,
	0xff,
	0xff,
	0x00,
	0xff,
	0x00,
	0xff,
	0xff,
	0xff,
	0xff,
	0x00,
	0xff,
	0xff,
	0x00,
	0xff,
	0x00,
	0xff,
	0x00,
	0x00,
	0xff,
	0xff,
	0x00,
	0xff,
	0x00,
	0xff,
	0x00,
	0x00,
	0xff,
	0xff,
	0x00,
	0xff,
	0x00,
	0xff,
	0x00,
};

static unsigned char AUTO_GAME_MID_2[] = {
	0xDE,
	0x84,
	0x28,
	0x96,
	0x05,
	0x01,
	0x50,
	0x01,
	0xd0,
	0x66,
	0x03,
	0x05,
	0x46,
	0x00,
	0x08,
	0x04,
	0x04,
	0x00,
	0x80,
	0x28,
	0x3e,
	0x7e,
	0xa0,
	0x28,
	0x18,
	0xa0,
	0x07,
	0x65,
	0x06,
	0x03,
	0x00,
	0x40,
	0x00,
	0x00,
	0x10,
	0x00,
	0x00,
	0x30,
	0x00,
	0x00,
	0x00,
	0x30,
	0x00,
	0x00,
	0x30,
	0x00,
	0x00,
	0x01,
	0xff,
	0x01,
	0x00,
	0x00,
	0x07,
	0xff,
	0x07,
	0xff,
	0x14,
	0x00,
	0x0a,
	0x00,
	0x32,
	0x01,
	0xf4,
	0x0b,
	0x8a,
	0x6e,
	0x99,
	0x1b,
	0x17,
	0x1e,
	0x1b,
	0x02,
	0x5f,
	0x03,
	0x33,
	0x02,
	0xc8,
	0x02,
	0x22,
	0x10,
	0x10,
	0x07,
	0x07,
	0x20,
	0x2d,
	0x01,
	0x00,
	0x00,
	0x08,
	0x00,
	0x08,
	0x00,
	0x08,
	0x00,
	0x08,
	0x00,
	0x08,
	0x00,
	0x08,
	0x02,
	0x8c,
	0x02,
	0x8c,
	0x02,
	0x8c,
	0x00,
	0x0a,
	0x00,
	0x0a,
	0x00,
	0x0a,
	0x00,
	0x0a,
	0x23,
	0xa0,
	0x23,
	0xa0,
	0x23,
	0xa0,
	0x23,
	0xa0,
	0x21,
	0x9f,
	0x20,
	0x9e,
	0x20,
	0x9e,
	0x20,
	0x9e,
	0x20,
	0x9e,
	0x20,
	0x9e,
	0x00,
	0xFF,
};

static unsigned char AUTO_GAME_MID_3[] = {
	0xDD,
	0x01,
	0x00,
	0x0f,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
};

static unsigned char AUTO_GAME_HIGH_1[] = {
	0xDF,
	0x00,
	0x14,
	0x01,
	0x6a,
	0x9a,
	0x25,
	0x1a,
	0x16,
	0x2a,
	0x00,
	0x37,
	0x5a,
	0x00,
	0x4e,
	0xc5,
	0x00,
	0x5d,
	0x17,
	0x00,
	0x30,
	0xc3,
	0xff,
	0x00,
	0x00,
	0xff,
	0xff,
	0x00,
	0xff,
	0x00,
	0xff,
	0xff,
	0xff,
	0xff,
	0x00,
	0xff,
	0xff,
	0x00,
	0xff,
	0x00,
	0xff,
	0x00,
	0x00,
	0xff,
	0xff,
	0x00,
	0xff,
	0x00,
	0xff,
	0x00,
	0x00,
	0xff,
	0xff,
	0x00,
	0xff,
	0x00,
	0xff,
	0x00,
};

static unsigned char AUTO_GAME_HIGH_2[] = {
	0xDE,
	0x84,
	0x28,
	0x96,
	0x05,
	0x01,
	0x60,
	0x01,
	0xf0,
	0x66,
	0x03,
	0x05,
	0x46,
	0x00,
	0x08,
	0x04,
	0x04,
	0x00,
	0x80,
	0x28,
	0x3e,
	0x7e,
	0xa0,
	0x28,
	0x18,
	0xa0,
	0x07,
	0x65,
	0x06,
	0x03,
	0x00,
	0x40,
	0x00,
	0x00,
	0x10,
	0x00,
	0x00,
	0x30,
	0x00,
	0x00,
	0x00,
	0x30,
	0x00,
	0x00,
	0x30,
	0x00,
	0x00,
	0x01,
	0xff,
	0x01,
	0x00,
	0x00,
	0x07,
	0xff,
	0x07,
	0xff,
	0x14,
	0x00,
	0x0a,
	0x00,
	0x32,
	0x01,
	0xf4,
	0x0b,
	0x8a,
	0x6e,
	0x99,
	0x1b,
	0x17,
	0x1e,
	0x1b,
	0x02,
	0x5f,
	0x03,
	0x33,
	0x02,
	0xc8,
	0x02,
	0x22,
	0x10,
	0x10,
	0x07,
	0x07,
	0x20,
	0x2d,
	0x01,
	0x00,
	0x00,
	0x0b,
	0x00,
	0x0b,
	0x00,
	0x0b,
	0x00,
	0x0b,
	0x00,
	0x0b,
	0x0c,
	0xa0,
	0x0c,
	0xa0,
	0x0c,
	0xa0,
	0x02,
	0x12,
	0x02,
	0x12,
	0x02,
	0x12,
	0x02,
	0x12,
	0x02,
	0x12,
	0x02,
	0x12,
	0x02,
	0x12,
	0x02,
	0x12,
	0x02,
	0x12,
	0x1e,
	0xa0,
	0x1e,
	0xa0,
	0x1e,
	0xa0,
	0x1e,
	0xa0,
	0x1e,
	0xa0,
	0x1e,
	0xa0,
	0x00,
	0xFF,
};

static unsigned char AUTO_GAME_HIGH_3[] = {
	0xDD,
	0x01,
	0x00,
	0x0f,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
};

static unsigned char HBM_AOLCE_1_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x6a, //ascr_skin_cb
	0x9a, //ascr_skin_cr
	0x25, //ascr_dist_up
	0x1a, //ascr_dist_down
	0x16, //ascr_dist_right
	0x2a, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x37,
	0x5a,
	0x00, //ascr_div_down
	0x4e,
	0xc5,
	0x00, //ascr_div_right
	0x5d,
	0x17,
	0x00, //ascr_div_left
	0x30,
	0xc3,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HBM_AOLCE_1_2[] = {
	0xDE,
	0x88, //lce_on gain 0 000 0000
	0x30, //lce_color_gain 00 0000
	0x40, //lce_min_ref_offset
	0xb0, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0xbf,
	0x00, //lce_ref_gain 9
	0xd0,
	0x77, //lce_block_size h v 0000 0000
	0x00, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x55, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x04, //lce_large_w
	0x06, //lce_med_w
	0x06, //lce_small_w
	0x00, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x01, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x40,
	0x00, //curve_1_b
	0x6b, //curve_1_a
	0x03, //curve_2_b
	0x48, //curve_2_a
	0x08, //curve_3_b
	0x32, //curve_3_a
	0x08, //curve_4_b
	0x32, //curve_4_a
	0x08, //curve_5_b
	0x32, //curve_5_a
	0x08, //curve_6_b
	0x32, //curve_6_a
	0x08, //curve_7_b
	0x32, //curve_7_a
	0x10, //curve_8_b
	0x28, //curve_8_a
	0x10, //curve_9_b
	0x28, //curve_9_a
	0x10, //curve10_b
	0x28, //curve10_a
	0x10, //curve11_b
	0x28, //curve11_a
	0x10, //curve12_b
	0x28, //curve12_a
	0x19, //curve13_b
	0x22, //curve13_a
	0x19, //curve14_b
	0x22, //curve14_a
	0x19, //curve15_b
	0x22, //curve15_a
	0x19, //curve16_b
	0x22, //curve16_a
	0x19, //curve17_b
	0x22, //curve17_a
	0x19, //curve18_b
	0x22, //curve18_a
	0x23, //curve19_b
	0x1e, //curve19_a
	0x2e, //curve20_b
	0x1b, //curve20_a
	0x33, //curve21_b
	0x1a, //curve21_a
	0x40, //curve22_b
	0x18, //curve22_a
	0x48, //curve23_b
	0x17, //curve23_a
	0x00, //curve24_b
	0xFF, //curve24_a
};

static unsigned char HBM_AOLCE_1_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3f, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char HMT_GRAY_8_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HMT_GRAY_8_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char HMT_GRAY_8_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x00, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char HMT_GRAY_16_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HMT_GRAY_16_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char HMT_GRAY_16_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x00, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

#ifdef CONFIG_LCD_HMT
static unsigned char HMT_3000K_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HMT_3000K_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char HMT_3000K_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x00, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char HMT_4000K_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HMT_4000K_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char HMT_4000K_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x00, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char HMT_5000K_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HMT_5000K_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char HMT_5000K_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x00, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char HMT_6500K_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xff, //ascr_skin_Rr
	0x00, //ascr_skin_Rg
	0x00, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char HMT_6500K_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x02, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x40,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char HMT_6500K_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};
#endif

#if defined(CONFIG_TDMB)
static unsigned char STANDARD_DMB_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xf1, //ascr_skin_Rr
	0x2f, //ascr_skin_Rg
	0x2e, //ascr_skin_Rb
	0xf2, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x45, //ascr_skin_Yb
	0xfb, //ascr_skin_Mr
	0x48, //ascr_skin_Mg
	0xe7, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xf1, //ascr_Rr
	0xef, //ascr_Cg
	0x2f, //ascr_Rg
	0xe9, //ascr_Cb
	0x2e, //ascr_Rb
	0xfb, //ascr_Mr
	0x00, //ascr_Gr
	0x48, //ascr_Mg
	0xdf, //ascr_Gg
	0xe7, //ascr_Mb
	0x00, //ascr_Gb
	0xf2, //ascr_Yr
	0x30, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x45, //ascr_Yb
	0xdf, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char STANDARD_DMB_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char STANDARD_DMB_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char NATURAL_DMB_1[] = {
	0xDF,
	0x70, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x17, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x27, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x59,
	0x0b,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x34,
	0x83,
	0xd2, //ascr_skin_Rr
	0x26, //ascr_skin_Rg
	0x26, //ascr_skin_Rb
	0xf3, //ascr_skin_Yr
	0xed, //ascr_skin_Yg
	0x58, //ascr_skin_Yb
	0xdd, //ascr_skin_Mr
	0x41, //ascr_skin_Mg
	0xe1, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xfa, //ascr_skin_Wg
	0xf1, //ascr_skin_Wb
	0x94, //ascr_Cr
	0xd2, //ascr_Rr
	0xf3, //ascr_Cg
	0x26, //ascr_Rg
	0xea, //ascr_Cb
	0x26, //ascr_Rb
	0xdd, //ascr_Mr
	0x8a, //ascr_Gr
	0x41, //ascr_Mg
	0xe7, //ascr_Gg
	0xe1, //ascr_Mb
	0x4e, //ascr_Gb
	0xf3, //ascr_Yr
	0x2a, //ascr_Br
	0xed, //ascr_Yg
	0x2f, //ascr_Bg
	0x58, //ascr_Yb
	0xdc, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xfa, //ascr_Wg
	0x00, //ascr_Kg
	0xf1, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char NATURAL_DMB_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x00,
	0x01, //de_maxplus 11
	0x00,
	0x01, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x70,
	0x01, //fa_pcl_ppi 14
	0xc0,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char NATURAL_DMB_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x30, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char DYNAMIC_DMB_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x37, //ascr_dist_up
	0x29, //ascr_dist_down
	0x19, //ascr_dist_right
	0x47, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x25,
	0x3d,
	0x00, //ascr_div_down
	0x31,
	0xf4,
	0x00, //ascr_div_right
	0x51,
	0xec,
	0x00, //ascr_div_left
	0x1c,
	0xd8,
	0xff, //ascr_skin_Rr
	0x60, //ascr_skin_Rg
	0x70, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xff, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xff, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf4, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char DYNAMIC_DMB_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x07, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x20,
	0x00, //curve_1_b
	0x14, //curve_1_a
	0x00, //curve_2_b
	0x14, //curve_2_a
	0x00, //curve_3_b
	0x14, //curve_3_a
	0x00, //curve_4_b
	0x14, //curve_4_a
	0x03, //curve_5_b
	0x9a, //curve_5_a
	0x03, //curve_6_b
	0x9a, //curve_6_a
	0x03, //curve_7_b
	0x9a, //curve_7_a
	0x03, //curve_8_b
	0x9a, //curve_8_a
	0x07, //curve_9_b
	0x9e, //curve_9_a
	0x07, //curve10_b
	0x9e, //curve10_a
	0x07, //curve11_b
	0x9e, //curve11_a
	0x07, //curve12_b
	0x9e, //curve12_a
	0x0a, //curve13_b
	0xa0, //curve13_a
	0x0a, //curve14_b
	0xa0, //curve14_a
	0x0a, //curve15_b
	0xa0, //curve15_a
	0x0a, //curve16_b
	0xa0, //curve16_a
	0x16, //curve17_b
	0xa6, //curve17_a
	0x16, //curve18_b
	0xa6, //curve18_a
	0x16, //curve19_b
	0xa6, //curve19_a
	0x16, //curve20_b
	0xa6, //curve20_a
	0x05, //curve21_b
	0x21, //curve21_a
	0x0b, //curve22_b
	0x20, //curve22_a
	0x87, //curve23_b
	0x0f, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char DYNAMIC_DMB_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char MOVIE_DMB_1[] = {
	0xDF,
	0x00, //linear_on ascr_skin_on strength 0 0 00000
	0x00, //ascr_trans_on ascr_trans_slope 0 0000
	0x00, //ascr_trans_interval 0000 0000
	0x67, //ascr_skin_cb
	0xa9, //ascr_skin_cr
	0x0c, //ascr_dist_up
	0x0c, //ascr_dist_down
	0x0c, //ascr_dist_right
	0x0c, //ascr_dist_left
	0x00, //ascr_div_up 20
	0xaa,
	0xab,
	0x00, //ascr_div_down
	0xaa,
	0xab,
	0x00, //ascr_div_right
	0xaa,
	0xab,
	0x00, //ascr_div_left
	0xaa,
	0xab,
	0xd5, //ascr_skin_Rr
	0x2c, //ascr_skin_Rg
	0x2a, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf5, //ascr_skin_Yg
	0x63, //ascr_skin_Yb
	0xfe, //ascr_skin_Mr
	0x4a, //ascr_skin_Mg
	0xff, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xf9, //ascr_skin_Wg
	0xf8, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xff, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xff, //ascr_Cb
	0x00, //ascr_Rb
	0xff, //ascr_Mr
	0x00, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xff, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x00, //ascr_Br
	0xff, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char MOVIE_DMB_2[] = {
	0xDE,
	0x18, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x67, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x01, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x28, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xa0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x06, //glare_luma_th 00 0000
	0x03, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0x00, //glare_blk_max_th 0000 0000
	0x00, //glare_blk_max_w 0000 0000
	0x10, //glare_blk_max_curve blk_max_sh 0 0000
	0x00, //glare_con_ext_max_th 0000 0000
	0x00, //glare_con_ext_max_w 0000 0000
	0x30, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x00, //glare_max_cnt_w 0000 0000
	0x30, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0x00, //glare_y_avg_th 0000 0000
	0x00, //glare_y_avg_w 0000 0000
	0x30, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x00, //glare_max_cnt_th_dmc 0000 0000
	0x00, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x01, //de_skin
	0x00, //de_gain 10
	0x00,
	0x07, //de_maxplus 11
	0xff,
	0x07, //de_maxminus 11
	0xff,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x0a,
	0x00, //fa_step_n 13
	0x32,
	0x01, //fa_max_de_gain 13
	0xf4,
	0x0b, //fa_pcl_ppi 14
	0x8a,
	0x6e, //fa_skin_cr
	0x99, //fa_skin_cb
	0x1b, //fa_dist_up
	0x17, //fa_dist_down
	0x1e, //fa_dist_right
	0x1b, //fa_dist_left
	0x02, //fa_div_dist_up
	0x5f,
	0x03, //fa_div_dist_down
	0x33,
	0x02, //fa_div_dist_right
	0xc8,
	0x02, //fa_div_dist_left
	0x22,
	0x10, //fa_px_min_weight
	0x10, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x20, //fa_os_cnt_10_co
	0x2d, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char MOVIE_DMB_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};

static unsigned char AUTO_DMB_1[] = {
	0xDF,
	0x30, //linear_on ascr_skin_on strength 0 0 00000
	0x14, //ascr_trans_on ascr_trans_slope 0 0000
	0x01, //ascr_trans_interval 0000 0000
	0x6a, //ascr_skin_cb
	0x9a, //ascr_skin_cr
	0x25, //ascr_dist_up
	0x1a, //ascr_dist_down
	0x16, //ascr_dist_right
	0x2a, //ascr_dist_left
	0x00, //ascr_div_up 20
	0x37,
	0x5a,
	0x00, //ascr_div_down
	0x4e,
	0xc5,
	0x00, //ascr_div_right
	0x5d,
	0x17,
	0x00, //ascr_div_left
	0x30,
	0xc3,
	0xff, //ascr_skin_Rr
	0x35, //ascr_skin_Rg
	0x4f, //ascr_skin_Rb
	0xff, //ascr_skin_Yr
	0xf0, //ascr_skin_Yg
	0x00, //ascr_skin_Yb
	0xd8, //ascr_skin_Mr
	0x00, //ascr_skin_Mg
	0xd9, //ascr_skin_Mb
	0xff, //ascr_skin_Wr
	0xff, //ascr_skin_Wg
	0xff, //ascr_skin_Wb
	0x00, //ascr_Cr
	0xe0, //ascr_Rr
	0xff, //ascr_Cg
	0x00, //ascr_Rg
	0xf6, //ascr_Cb
	0x00, //ascr_Rb
	0xd8, //ascr_Mr
	0x3b, //ascr_Gr
	0x00, //ascr_Mg
	0xff, //ascr_Gg
	0xd9, //ascr_Mb
	0x00, //ascr_Gb
	0xff, //ascr_Yr
	0x14, //ascr_Br
	0xf9, //ascr_Yg
	0x00, //ascr_Bg
	0x00, //ascr_Yb
	0xff, //ascr_Bb
	0xff, //ascr_Wr
	0x00, //ascr_Kr
	0xff, //ascr_Wg
	0x00, //ascr_Kg
	0xff, //ascr_Wb
	0x00, //ascr_Kb
};

static unsigned char AUTO_DMB_2[] = {
	0xDE,
	0x00, //lce_on gain 0 000 0000
	0x24, //lce_color_gain 00 0000
	0x96, //lce_min_ref_offset
	0xb3, //lce_illum_gain
	0x01, //lce_ref_offset 9
	0x0e,
	0x01, //lce_ref_gain 9
	0x00,
	0x77, //lce_block_size h v 0000 0000
	0x03, //lce_dark_th 000
	0x07, //lce_reduct_slope 0000
	0x40, //lce_black cc0 cc1 color_th 0 0 0 0000
	0x00, //lce_adaptive_slce adaptive_illum adaptive_reflect 0 0 0
	0x08, //lce_large_w
	0x04, //lce_med_w
	0x04, //lce_small_w
	0x0c, //glare_on uni_mode luma_ctrl_sel chroma_ctrl_sel 0 0 0 0
	0x80, //glare_blk_avg_th 0000 0000
	0x00, //glare_luma_gain 000 0000
	0x3e, //glare_luma_gain_min 000 0000
	0x7e, //glare_luma_en 0000 0000
	0xc0, //glare_luma_ctl_start 0000 0000
	0x28, //glare_luma_gain_min_th 0000 0000
	0x18, //glare_chroma_inf 0 0000
	0xa0, //glare_chroma_min 0000 0000
	0x07, //glare_chroma_gain 0 0000
	0x65, //glare_chroma_blk_th 0000 0000
	0x00, //glare_luma_th 00 0000
	0x01, //glare_luma_step 000 0000
	0x00, //glare_luma_upper_limit 0000 0000
	0x40, //glare_uni_luma_gain 000 0000
	0xf0, //glare_blk_max_th 0000 0000
	0x89, //glare_blk_max_w 0000 0000
	0x18, //glare_blk_max_curve blk_max_sh 0 0000
	0xf0, //glare_con_ext_max_th 0000 0000
	0x89, //glare_con_ext_max_w 0000 0000
	0x38, //glare_con_ext_max_sign con_ext_max_curve con_ext_max_sh 0 0 0000
	0x00, //glare_max_cnt_th 0000
	0x00, //glare_max_cnt_th 0000 0000
	0x0c, //glare_max_cnt_w 0000 0000
	0x38, //glare_max_cnt_sign max_cnt_curve max_cnt_sh 0 0 0000
	0xba, //glare_y_avg_th 0000 0000
	0x1e, //glare_y_avg_w 0000 0000
	0x38, //glare_y_avg_sign y_avg_curve y_avg_sh 0 0 0000
	0x00, //glare_max_cnt_th_dmc 0000
	0x05, //glare_max_cnt_th_dmc 0000 0000
	0x0c, //nr fa de cs gamma 0 0000
	0xff, //nr_mask_th
	0x00, //de_skin
	0x00, //de_gain 10
	0x10,
	0x02, //de_maxplus 11
	0x00,
	0x02, //de_maxminus 11
	0x00,
	0x14, //fa_edge_th
	0x00, //fa_step_p 13
	0x01,
	0x00, //fa_step_n 13
	0x01,
	0x00, //fa_max_de_gain 13
	0x10,
	0x00, //fa_pcl_ppi 14
	0x00,
	0x67, //fa_skin_cb
	0xa9, //fa_skin_cr
	0x17, //fa_dist_up
	0x29, //fa_dist_down
	0x19, //fa_dist_right
	0x27, //fa_dist_left
	0x02, //fa_div_dist_up
	0xc8,
	0x01, //fa_div_dist_down
	0x90,
	0x02, //fa_div_dist_right
	0x8f,
	0x01, //fa_div_dist_left
	0xa4,
	0x20, //fa_px_min_weight
	0x20, //fa_fr_min_weight
	0x07, //fa_skin_zone_w
	0x07, //fa_skin_zone_h
	0x28, //fa_os_cnt_10_co
	0x3c, //fa_os_cnt_20_co
	0x01, //cs_gain 10
	0x00,
	0x00, //curve_1_b
	0x20, //curve_1_a
	0x00, //curve_2_b
	0x20, //curve_2_a
	0x00, //curve_3_b
	0x20, //curve_3_a
	0x00, //curve_4_b
	0x20, //curve_4_a
	0x00, //curve_5_b
	0x20, //curve_5_a
	0x00, //curve_6_b
	0x20, //curve_6_a
	0x00, //curve_7_b
	0x20, //curve_7_a
	0x00, //curve_8_b
	0x20, //curve_8_a
	0x00, //curve_9_b
	0x20, //curve_9_a
	0x00, //curve10_b
	0x20, //curve10_a
	0x00, //curve11_b
	0x20, //curve11_a
	0x00, //curve12_b
	0x20, //curve12_a
	0x00, //curve13_b
	0x20, //curve13_a
	0x00, //curve14_b
	0x20, //curve14_a
	0x00, //curve15_b
	0x20, //curve15_a
	0x00, //curve16_b
	0x20, //curve16_a
	0x00, //curve17_b
	0x20, //curve17_a
	0x00, //curve18_b
	0x20, //curve18_a
	0x00, //curve19_b
	0x20, //curve19_a
	0x00, //curve20_b
	0x20, //curve20_a
	0x00, //curve21_b
	0x20, //curve21_a
	0x00, //curve22_b
	0x20, //curve22_a
	0x00, //curve23_b
	0x20, //curve23_a
	0x00, //curve24_b
	0xff, //curve24_a
};

static unsigned char AUTO_DMB_3[] = {
	0xDD,
	0x01, //mdnie_en
	0x00, //mask 0000
	0x3c, //ascr algo aolce 00 00 00
	0x00, //gam_scr_bypass 00
	0x00, //agm_bypass_mode cc_bypass_mode cs_bypass_mode fa_de_bypass_mode 00 00 00 00
	0x00, //fa_bypass_mode nr_bypass_mode glare_bypass_mode aolce_bypass_mode 00 00 00 00
	0x00, //ap_roi_mode ddi_roi_en 000 0
	0x00, //ap_roi_sx 0000
	0x00, //ap_roi_sx 0000 0000
	0x00, //ap_roi_sy 0000
	0x00, //ap_roi_sy 0000 0000
	0x00, //ap_roi_ex 0000
	0x00, //ap_roi_ex 0000 0000
	0x00, //ap_roi_ey 0000
	0x00, //ap_roi_ey 0000 0000
};
#endif

static unsigned char LEVEL_UNLOCK[] = {
	0xF0,
	0x5A, 0x5A
};

static unsigned char LEVEL_LOCK[] = {
	0xF0,
	0xA5, 0xA5
};

#define MDNIE_SET(id)	\
{							\
	.name		= #id,				\
	.update_flag	= {0, 1, 2, 3, 0},		\
	.seq		= {				\
		{	.cmd = LEVEL_UNLOCK,	.len = ARRAY_SIZE(LEVEL_UNLOCK),	.sleep = 0,},	\
		{	.cmd = id##_1,	.len = ARRAY_SIZE(id##_1),	.sleep = 0,},	\
		{	.cmd = id##_2,	.len = ARRAY_SIZE(id##_2),	.sleep = 0,},	\
		{	.cmd = id##_3,	.len = ARRAY_SIZE(id##_3),	.sleep = 0,},	\
		{	.cmd = LEVEL_LOCK,	.len = ARRAY_SIZE(LEVEL_LOCK),		.sleep = 0,},	\
	}	\
}

static struct mdnie_table bypass_table[BYPASS_MAX] = {
	[BYPASS_ON] = MDNIE_SET(BYPASS)
};

static struct mdnie_table accessibility_table[ACCESSIBILITY_MAX] = {
	[NEGATIVE] = MDNIE_SET(NEGATIVE),
	MDNIE_SET(COLOR_BLIND),
	MDNIE_SET(SCREEN_CURTAIN),
	MDNIE_SET(GRAYSCALE),
	MDNIE_SET(GRAYSCALE_NEGATIVE),
	MDNIE_SET(COLOR_BLIND)
};

static struct mdnie_table hbm_table[HBM_MAX] = {
	[HBM_ON] = MDNIE_SET(HBM_AOLCE_1)
};

#ifdef CONFIG_LCD_HMT
static struct mdnie_table hmt_table[HMT_MDNIE_MAX] = {
	[HMT_MDNIE_ON] = MDNIE_SET(HMT_3000K),
	MDNIE_SET(HMT_4000K),
	MDNIE_SET(HMT_5000K),
	MDNIE_SET(HMT_6500K)
};
#endif

#if defined(CONFIG_TDMB)
static struct mdnie_table dmb_table[MODE_MAX] = {
	MDNIE_SET(DYNAMIC_DMB),
	MDNIE_SET(STANDARD_DMB),
	MDNIE_SET(NATURAL_DMB),
	MDNIE_SET(MOVIE_DMB),
	MDNIE_SET(AUTO_DMB)
};
#endif

static struct mdnie_table hdr_table[HDR_MAX] = {
	[HDR_ON] = MDNIE_SET(HDR_VIDEO_1),
	MDNIE_SET(HDR_VIDEO_2),
	MDNIE_SET(HDR_VIDEO_3)
};

static struct mdnie_table night_table[NIGHT_MODE_MAX] = {
	[NIGHT_MODE_ON] = MDNIE_SET(NIGHT_MODE)
};

static struct mdnie_table lens_table[COLOR_LENS_MAX] = {
	[COLOR_LENS_ON] = MDNIE_SET(COLOR_LENS)
};

static struct mdnie_table light_notification_table[LIGHT_NOTIFICATION_MAX] = {
	[LIGHT_NOTIFICATION_ON] = MDNIE_SET(LIGHT_NOTIFICATION)
};

static struct mdnie_table main_table[SCENARIO_MAX][MODE_MAX] = {
	{
		MDNIE_SET(DYNAMIC_UI),
		MDNIE_SET(STANDARD_UI),
		MDNIE_SET(NATURAL_UI),
		MDNIE_SET(MOVIE_UI),
		MDNIE_SET(AUTO_UI)
	}, {
		MDNIE_SET(DYNAMIC_VIDEO),
		MDNIE_SET(STANDARD_VIDEO),
		MDNIE_SET(NATURAL_VIDEO),
		MDNIE_SET(MOVIE_VIDEO),
		MDNIE_SET(AUTO_VIDEO)
	},
	[CAMERA_MODE] = {
		MDNIE_SET(DYNAMIC_CAMERA),
		MDNIE_SET(STANDARD_CAMERA),
		MDNIE_SET(NATURAL_CAMERA),
		MDNIE_SET(MOVIE_CAMERA),
		MDNIE_SET(AUTO_CAMERA)
	},
	[GALLERY_MODE] = {
		MDNIE_SET(DYNAMIC_GALLERY),
		MDNIE_SET(STANDARD_GALLERY),
		MDNIE_SET(NATURAL_GALLERY),
		MDNIE_SET(MOVIE_GALLERY),
		MDNIE_SET(AUTO_GALLERY)
	}, {
		MDNIE_SET(DYNAMIC_VT),
		MDNIE_SET(STANDARD_VT),
		MDNIE_SET(NATURAL_VT),
		MDNIE_SET(MOVIE_VT),
		MDNIE_SET(AUTO_VT)
	}, {
		MDNIE_SET(DYNAMIC_BROWSER),
		MDNIE_SET(STANDARD_BROWSER),
		MDNIE_SET(NATURAL_BROWSER),
		MDNIE_SET(MOVIE_BROWSER),
		MDNIE_SET(AUTO_BROWSER)
	}, {
		MDNIE_SET(DYNAMIC_EBOOK),
		MDNIE_SET(STANDARD_EBOOK),
		MDNIE_SET(NATURAL_EBOOK),
		MDNIE_SET(MOVIE_EBOOK),
		MDNIE_SET(AUTO_EBOOK)
	}, {
		MDNIE_SET(AUTO_EMAIL),
		MDNIE_SET(AUTO_EMAIL),
		MDNIE_SET(AUTO_EMAIL),
		MDNIE_SET(AUTO_EMAIL),
		MDNIE_SET(AUTO_EMAIL)
	}, {
		MDNIE_SET(AUTO_GAME_LOW),
		MDNIE_SET(AUTO_GAME_LOW),
		MDNIE_SET(AUTO_GAME_LOW),
		MDNIE_SET(AUTO_GAME_LOW),
		MDNIE_SET(AUTO_GAME_LOW)
	}, {
		MDNIE_SET(AUTO_GAME_MID),
		MDNIE_SET(AUTO_GAME_MID),
		MDNIE_SET(AUTO_GAME_MID),
		MDNIE_SET(AUTO_GAME_MID),
		MDNIE_SET(AUTO_GAME_MID)
	}, {
		MDNIE_SET(AUTO_GAME_HIGH),
		MDNIE_SET(AUTO_GAME_HIGH),
		MDNIE_SET(AUTO_GAME_HIGH),
		MDNIE_SET(AUTO_GAME_HIGH),
		MDNIE_SET(AUTO_GAME_HIGH)
	}, {
		MDNIE_SET(VIDEO_ENHANCER),
		MDNIE_SET(VIDEO_ENHANCER),
		MDNIE_SET(VIDEO_ENHANCER),
		MDNIE_SET(VIDEO_ENHANCER),
		MDNIE_SET(VIDEO_ENHANCER)
	}, {
		MDNIE_SET(VIDEO_ENHANCER_THIRD),
		MDNIE_SET(VIDEO_ENHANCER_THIRD),
		MDNIE_SET(VIDEO_ENHANCER_THIRD),
		MDNIE_SET(VIDEO_ENHANCER_THIRD),
		MDNIE_SET(VIDEO_ENHANCER_THIRD)
	}, {
		MDNIE_SET(HMT_GRAY_8),
		MDNIE_SET(HMT_GRAY_8),
		MDNIE_SET(HMT_GRAY_8),
		MDNIE_SET(HMT_GRAY_8),
		MDNIE_SET(HMT_GRAY_8)
	}, {
		MDNIE_SET(HMT_GRAY_16),
		MDNIE_SET(HMT_GRAY_16),
		MDNIE_SET(HMT_GRAY_16),
		MDNIE_SET(HMT_GRAY_16),
		MDNIE_SET(HMT_GRAY_16)
	}
};

#undef MDNIE_SET

static struct mdnie_tune tune_info = {
	.bypass_table = bypass_table,
	.accessibility_table = accessibility_table,
	.hbm_table = hbm_table,
	.night_table = night_table,
	.lens_table = lens_table,
	.light_notification_table = light_notification_table,
#ifdef CONFIG_LCD_HMT
	.hmt_table = hmt_table,
#endif
#if defined(CONFIG_TDMB)
	.dmb_table = dmb_table,
#endif
	.hdr_table = hdr_table,
	.main_table = main_table,

	.coordinate_table = coordinate_data,
	.adjust_ldu_table = adjust_ldu_data,
	.night_mode_table = night_mode_data,
	.color_lens_table = color_lens_data,
	.scr_info = &scr_info,
	.trans_info = &trans_info,
	.night_info = &night_info,
	.color_lens_info = &color_lens_info,
	.get_hbm_index = get_hbm_index,
	.color_offset = {NULL, color_offset_f1, color_offset_f2, color_offset_f3, color_offset_f4}
};

#endif
