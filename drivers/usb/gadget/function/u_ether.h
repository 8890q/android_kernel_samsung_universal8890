/*
 * u_ether.h -- interface to USB gadget "ethernet link" utilities
 *
 * Copyright (C) 2003-2005,2008 David Brownell
 * Copyright (C) 2003-2004 Robert Schwebel, Benedikt Spranger
 * Copyright (C) 2008 Nokia Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __U_ETHER_H
#define __U_ETHER_H

#include <linux/err.h>
#include <linux/if_ether.h>
#include <linux/usb/composite.h>
#include <linux/usb/cdc.h>

/* #define CONFIG_USB_NCM_ACCUMULATE_MULTPKT */

#ifdef CONFIG_USB_NCM_ACCUMULATE_MULTPKT
/* #define DEBUG_USB_NCM */
#ifdef DEBUG_USB_NCM
#define DEBUG_NCM(fmt, args...) printk(fmt, ##args)
#else
#define DEBUG_NCM(fmt, args...) do {} while (0)
#endif
#endif

#include "gadget_chips.h"

struct eth_dev;

/*
 * This represents the USB side of an "ethernet" link, managed by a USB
 * function which provides control and (maybe) framing.  Two functions
 * in different configurations could share the same ethernet link/netdev,
 * using different host interaction models.
 *
 * There is a current limitation that only one instance of this link may
 * be present in any given configuration.  When that's a problem, network
 * layer facilities can be used to package multiple logical links on this
 * single "physical" one.
 */
struct gether {
	struct usb_function		func;

	/* updated by gether_{connect,disconnect} */
	struct eth_dev			*ioport;

	/* endpoints handle full and/or high speeds */
	struct usb_ep			*in_ep;
	struct usb_ep			*out_ep;

	bool				is_zlp_ok;

	u16				cdc_filter;

	/* hooks for added framing, as needed for RNDIS and EEM. */
	u32				header_len;
	/* NCM requires fixed size bundles */
	bool				is_fixed;
	u32				fixed_out_len;
	u32				fixed_in_len;
#ifdef CONFIG_USB_RNDIS_MULTIPACKET
	unsigned			ul_max_pkts_per_xfer;
	unsigned			dl_max_pkts_per_xfer;
	bool				multi_pkt_xfer;

#ifdef CONFIG_USB_NCM_ACCUMULATE_MULTPKT
	void				*header;
	u16				ndp0_offset;
	u16				ndp0_blocklengthoffset;
	u16				ndp0_defaultBlockLen;
#else
	struct rndis_packet_msg_type	*header;
#endif /* CONFIG_USB_NCM_ACCUMULATE_MULTPKT */
#endif /* CONFIG_USB_RNDIS_MULTIPACKET */
	struct sk_buff			*(*wrap)(struct gether *port,
						struct sk_buff *skb);
	int				(*unwrap)(struct gether *port,
						struct sk_buff *skb,
						struct sk_buff_head *list);

	/* called on network open/close */
	void				(*open)(struct gether *);
	void				(*close)(struct gether *);
};

#define	DEFAULT_FILTER	(USB_CDC_PACKET_TYPE_BROADCAST \
			|USB_CDC_PACKET_TYPE_ALL_MULTICAST \
			|USB_CDC_PACKET_TYPE_PROMISCUOUS \
			|USB_CDC_PACKET_TYPE_DIRECTED)

/* variant of gether_setup that allows customizing network device name */
struct eth_dev *gether_setup_name(struct usb_gadget *g, u8 ethaddr[ETH_ALEN],
		const char *netname);

/* netdev setup/teardown as directed by the gadget driver */
/* gether_setup - initialize one ethernet-over-usb link
 * @g: gadget to associated with these links
 * @ethaddr: NULL, or a buffer in which the ethernet address of the
 *	host side of the link is recorded
 * Context: may sleep
 *
 * This sets up the single network link that may be exported by a
 * gadget driver using this framework.  The link layer addresses are
 * set up using module parameters.
 *
 * Returns negative errno, or zero on success
 */
static inline struct eth_dev *gether_setup(struct usb_gadget *g,
		u8 ethaddr[ETH_ALEN])
{
	return gether_setup_name(g, ethaddr, "usb");
}

void gether_cleanup(struct eth_dev *dev);

/* connect/disconnect is handled by individual functions */
struct net_device *gether_connect(struct gether *);
void gether_disconnect(struct gether *);

/* Some controllers can't support CDC Ethernet (ECM) ... */
static inline bool can_support_ecm(struct usb_gadget *gadget)
{
	if (!gadget_supports_altsettings(gadget))
		return false;

	/* Everything else is *presumably* fine ... but this is a bit
	 * chancy, so be **CERTAIN** there are no hardware issues with
	 * your controller.  Add it above if it can't handle CDC.
	 */
	return true;
}

/* each configuration may bind one instance of an ethernet link */
int geth_bind_config(struct usb_configuration *c, u8 ethaddr[ETH_ALEN],
		struct eth_dev *dev);
int ecm_bind_config(struct usb_configuration *c, u8 ethaddr[ETH_ALEN],
		struct eth_dev *dev);
int ncm_bind_config(struct usb_configuration *c, u8 ethaddr[ETH_ALEN],
		struct eth_dev *dev);
int eem_bind_config(struct usb_configuration *c, struct eth_dev *dev);

#ifdef USB_ETH_RNDIS

int rndis_bind_config_vendor(struct usb_configuration *c, u8 ethaddr[ETH_ALEN],
		u32 vendorID, const char *manufacturer, struct eth_dev *dev);

#else

static inline int
rndis_bind_config_vendor(struct usb_configuration *c, u8 ethaddr[ETH_ALEN],
		u32 vendorID, const char *manufacturer, struct eth_dev *dev)
{
	return 0;
}

#endif

/**
 * rndis_bind_config - add RNDIS network link to a configuration
 * @c: the configuration to support the network link
 * @ethaddr: a buffer in which the ethernet address of the host side
 *	side of the link was recorded
 * Context: single threaded during gadget setup
 *
 * Returns zero on success, else negative errno.
 *
 * Caller must have called @gether_setup().  Caller is also responsible
 * for calling @gether_cleanup() before module unload.
 */
static inline int rndis_bind_config(struct usb_configuration *c,
		u8 ethaddr[ETH_ALEN], struct eth_dev *dev)
{
	return rndis_bind_config_vendor(c, ethaddr, 0, NULL, dev);
}


#endif /* __U_ETHER_H */
