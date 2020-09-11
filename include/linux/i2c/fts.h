#ifndef _LINUX_FTS_I2C_H_
#define _LINUX_FTS_I2C_H_

//#define FTS_SUPPORT_NOISE_PARAM
#define FTS_SUPPORT_TOUCH_KEY
#define FTS_SUPPORT_SEC_SWIPE
#define FTS_SUPPORT_SIDE_GESTURE
//#define FTS_SUPPORT_WATER_MODE
/*#define FTS_SUPPORT_2NDSCREEN*/
/*#define FTS_SUPPORT_SIDE_SCROLL*/

#define FTS_SUPPORT_STRINGLIB
#undef FTS_SUPPORT_HOVER

extern struct fts_callbacks *fts_charger_callbacks;
struct fts_callbacks {
	void (*inform_charger) (struct fts_callbacks *, int);
};

#ifdef FTS_SUPPORT_NOISE_PARAM
#define MAX_NOISE_PARAM 5
struct fts_noise_param {
	unsigned short pAddr[MAX_NOISE_PARAM];
	unsigned short pData[MAX_NOISE_PARAM];
};
#endif

#ifdef FTS_SUPPORT_TOUCH_KEY
/* TSP Key Feature*/
#define KEY_PRESS       1
#define KEY_RELEASE     0
#define TOUCH_KEY_NULL	0

/* support 2 touch keys */
#define TOUCH_KEY_RECENT		0x01
#define TOUCH_KEY_BACK		0x02

struct fts_touchkey {
	unsigned int value;
	unsigned int keycode;
	char *name;
};
#endif

struct fts_i2c_platform_data {
	bool factory_flatform;
	bool recovery_mode;
	bool support_hover;
	bool support_mshover;
	int max_x;
	int max_y;
	int max_width;
	int grip_area;
	int SenseChannelLength;
	int ForceChannelLength;
	unsigned char panel_revision;	/* to identify panel info */

	const char *firmware_name;
	const char *project_name;
	const char *model_name;
	const char *regulator_dvdd;
	const char *regulator_avdd;

	struct pinctrl *pinctrl;
	struct pinctrl_state	*pins_default;
	struct pinctrl_state	*pins_sleep;

	int (*power)(void *data, bool on);
	void (*register_cb)(void *);
	void (*enable_sync)(bool on);
	unsigned char (*get_ddi_type)(void);	/* to indentify ddi type */

	unsigned tspid;
	unsigned tspid2;
	unsigned gpio;
	int irq_type;
	int stm_ver;
	u32	device_num;

#ifdef FTS_SUPPORT_TOUCH_KEY
	bool support_mskey;
	unsigned int num_touchkey;
	struct fts_touchkey *touchkey;
	const char *regulator_tk_led;
	int (*led_power) (void *, bool);
#endif
#ifdef FTS_SUPPORT_SIDE_GESTURE
	int support_sidegesture;
#endif
#ifdef FTS_SUPPORT_2NDSCREEN
	bool support_2ndscreen;
#endif
#ifdef FTS_SUPPORT_SIDE_SCROLL
	bool support_sidescroll;
#endif
	unsigned gpio_scl;
	unsigned gpio_sda;
};

#define SEC_TSP_FACTORY_TEST

// #define FTS_SUPPORT_TA_MODE // DE version don't need.

#ifdef SEC_TSP_FACTORY_TEST
extern struct class *sec_class;
#endif

extern unsigned int lcdtype;

void fts_charger_infom(bool en);
#ifdef CONFIG_TRUSTONIC_TRUSTED_UI
extern void trustedui_mode_on(void);
#endif
#endif
